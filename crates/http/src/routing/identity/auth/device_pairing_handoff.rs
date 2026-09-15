//! The two authenticated halves of the server-mediated device-pairing handoff
//! (`crypto-media/device-lifecycle.md` §2.1.1 clauses 2 and 5):
//!
//! - `POST /_arkret/gate/account/device-pairing/finalizations` —
//!   `ak.gate.account.command.finalize_device_pairing.v1`
//! - `POST /_arkret/gate/account/device-pairing/code-claims` —
//!   `ak.gate.account.read.claim_device_pairing_code.v1`
//!
//! These belong to the Account Authority behind `gate_audience`, so they are
//! advertised with `ak.operation_bundle.station.http_core.v1` and never with the
//! unauthenticated `ak.operation_bundle.station.device_pairing_handoff.v1`.
//!
//! Both surfaces are uniformly anti-enumerating: every failure shape collapses
//! to the same `not_found`. Authentication does not relax that — an authorized
//! device must not be able to learn from the error whether a code exists, which
//! account owns it, or which device it names.

use arkret_models_collaboration::http_bodies::{
    DevicePairingBootstrap, DevicePairingCode, DevicePairingCodeClaimOutcome,
    DevicePairingCodeClaimRequestBody, DevicePairingFinalizeOutcome,
    DevicePairingFinalizeRequestBody, DevicePairingNonce, DevicePairingReadyForClaimState,
    DevicePairingRequestId, DevicePairingState, DevicePairingTargetProof,
};

use super::*;

#[salvo::oapi::endpoint(
    operation_id = "ak.gate.account.command.finalize_device_pairing",
    summary = "Bind a staged device pairing request to its account",
    tags("account")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.gate.account.command.finalize_device_pairing.v1")
)]
pub(super) async fn finalize_device_pairing(
    aa: super::super::AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<DevicePairingFinalizeRequestBody>,
) -> JsonResult<DevicePairingFinalizeOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let account_id = handoff_account(state, &session).await?;
    let body = body.into_inner();
    let now = now();
    let record = live_pairing_record(
        state
            .device_pairings()
            .get(body.device_pairing_request_id.as_str())
            .await
            .map_err(pairing_lookup_failed)?,
        now,
    )?;
    if record.pairing_code != body.pairing_code.as_str() {
        return Err(device_pairing_not_found());
    }
    // Finalize is the `staged -> ready_for_claim` edge. A record that already
    // left `staged` is only acceptable as the byte-identical retry the store
    // resolves below; any other state is masked.
    if record.state != DevicePairingState::Staged
        && record.state != DevicePairingState::ReadyForClaim
    {
        return Err(device_pairing_not_found());
    }
    let challenge = pairing_challenge(&record, &body.pairing_code)?;
    let new_device_pubkey = staged_public_key(&record)?;
    // The account comes from the presented handoff credential, never from the
    // body: `expected_account_id` is what makes the signed `account_id` member
    // of the proof an account binding rather than a self-asserted label.
    arkret_signatures::device_pairing::verify_server_device_pairing_target_proof(
        &new_device_pubkey,
        &challenge,
        &account_id,
        &body.target_proof,
        now,
    )
    .map_err(|_| device_pairing_not_found())?;
    let target_proof = serde_json::to_value(&body.target_proof)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let finalized = state
        .device_pairings()
        .finalize(
            body.device_pairing_request_id.as_str(),
            &account_id,
            target_proof,
            now,
        )
        .await
        .map_err(|error| {
            if error.kind() == soland_services::ServiceErrorKind::NotFound {
                device_pairing_not_found()
            } else {
                AppError::conflict(error.detail())
            }
        })?;
    json_ok(DevicePairingFinalizeOutcome {
        device_pairing_request_id: DevicePairingRequestId::new(finalized.device_pairing_request_id)
            .map_err(|error| AppError::internal(error.to_string()))?,
        state: DevicePairingReadyForClaimState::ReadyForClaim,
        expires_at: finalized.expires_at,
    })
}

#[salvo::oapi::endpoint(
    operation_id = "ak.gate.account.read.claim_device_pairing_code",
    summary = "Claim a device pairing code",
    tags("account")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.gate.account.read.claim_device_pairing_code.v1")
)]
pub(super) async fn claim_device_pairing_code(
    aa: super::super::AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<DevicePairingCodeClaimRequestBody>,
) -> JsonResult<DevicePairingCodeClaimOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let account_id = handoff_account(state, &session).await?;
    // Claiming is reserved to an accepted, non-`revocation_pending` device of
    // the account itself. A caller that fails this gate learns nothing about
    // the code it submitted.
    ensure_claiming_device_accepted(state, &session).await?;
    let body = body.into_inner();
    let record = live_pairing_record(
        state
            .device_pairings()
            .get_by_pairing_code(body.pairing_code.as_str())
            .await
            .map_err(pairing_lookup_failed)?,
        now(),
    )?;
    if record.state != DevicePairingState::ReadyForClaim
        || record.account_id.as_ref() != Some(&account_id)
    {
        return Err(device_pairing_not_found());
    }
    let pairing_code = DevicePairingCode::new(record.pairing_code.clone())
        .map_err(|error| AppError::internal(format!("stored pairing_code invalid: {error}")))?;
    let challenge = pairing_challenge(&record, &pairing_code)?;
    let new_device_pubkey = staged_public_key(&record)?;
    let target_proof: DevicePairingTargetProof = serde_json::from_value(
        record
            .target_proof
            .clone()
            .ok_or_else(|| AppError::internal("finalized pairing has no target proof"))?,
    )
    .map_err(|error| AppError::internal(format!("stored target_proof invalid: {error}")))?;
    // The claim path re-verifies the same proof against the same transcript the
    // short-link resolve path uses, so entering a code is never a weaker branch.
    arkret_signatures::device_pairing::verify_server_device_pairing_target_proof(
        &new_device_pubkey,
        &challenge,
        &account_id,
        &target_proof,
        now(),
    )
    .map_err(|_| device_pairing_not_found())?;
    json_ok(DevicePairingCodeClaimOutcome {
        device_pairing_request_id: DevicePairingRequestId::new(
            record.device_pairing_request_id.clone(),
        )
        .map_err(|error| AppError::internal(error.to_string()))?,
        bootstrap: pairing_bootstrap(state, &record, pairing_code)?,
        target_proof,
    })
}

async fn handoff_account(
    state: &AppState,
    session: &SessionRecord,
) -> Result<arkret_wire::AccountId, AppError> {
    let account_id =
        crate::routing::identity::auth_grant_dpop::authenticated_session_account_id(state, session)
            .await?;
    if state.device_pairing_handoff_rate_limited(&session.device_id, &account_id.to_string()) {
        return Err(AppError::from_rejection(
            arkret_wire::ErrorCode::RateLimited,
            "device pairing handoff quota exhausted",
        ));
    }
    Ok(account_id)
}

async fn ensure_claiming_device_accepted(
    state: &AppState,
    session: &SessionRecord,
) -> Result<(), AppError> {
    let device = state
        .identities()
        .find_device(soland_services::identity::FindDeviceQuery {
            actor_id: session.actor.clone(),
            device_id: session.device_id.clone(),
        })
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(device_pairing_not_found)?;
    if device.revoked_at.is_some() || device.verification_state != "verified" {
        return Err(device_pairing_not_found());
    }
    if crate::routing::identity::auth::is_device_revoked(state, &session.actor, &session.device_id)
        .await
    {
        return Err(device_pairing_not_found());
    }
    Ok(())
}

/// Collapse "absent" and "window elapsed" into the single masked outcome both
/// surfaces owe every failure shape.
fn live_pairing_record(
    record: Option<soland_services::identity::DevicePairingState>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<soland_services::identity::DevicePairingState, AppError> {
    record
        .filter(|record| record.expires_at > now)
        .ok_or_else(device_pairing_not_found)
}

fn pairing_challenge(
    record: &soland_services::identity::DevicePairingState,
    pairing_code: &DevicePairingCode,
) -> Result<arkret_signatures::device_pairing::ServerDevicePairingChallenge, AppError> {
    Ok(
        arkret_signatures::device_pairing::ServerDevicePairingChallenge {
            display_name: record
                .display_name
                .clone()
                .map(arkret_wire::NonEmptyString::new)
                .transpose()
                .map_err(|error| AppError::internal(error.to_string()))?,
            device_metadata: record
                .device_metadata
                .clone()
                .map(serde_json::from_value)
                .transpose()
                .map_err(|error| AppError::internal(error.to_string()))?,
            client_nonce: DevicePairingNonce::new(record.client_nonce.clone())
                .map_err(|error| AppError::internal(error.to_string()))?,
            device_pairing_request_id: DevicePairingRequestId::new(
                record.device_pairing_request_id.clone(),
            )
            .map_err(|error| AppError::internal(error.to_string()))?,
            expires_at: record.expires_at,
            gate_audience_uri: record.gate_audience.clone(),
            pairing_code: pairing_code.clone(),
            server_nonce: DevicePairingNonce::new(record.server_nonce.clone())
                .map_err(|error| AppError::internal(error.to_string()))?,
        },
    )
}

fn staged_public_key(
    record: &soland_services::identity::DevicePairingState,
) -> Result<arkret_models_collaboration::governance::agent_artifacts::PublicKey, AppError> {
    serde_json::from_value(record.new_device_pubkey.clone())
        .map_err(|error| AppError::internal(format!("stored new_device_pubkey invalid: {error}")))
}

fn pairing_bootstrap(
    state: &AppState,
    record: &soland_services::identity::DevicePairingState,
    pairing_code: DevicePairingCode,
) -> Result<DevicePairingBootstrap, AppError> {
    Ok(DevicePairingBootstrap {
        arkret_base_url: state
            .config()
            .public_base_url
            .trim_end_matches('/')
            .to_owned(),
        device_pairing_request_id: DevicePairingRequestId::new(
            record.device_pairing_request_id.clone(),
        )
        .map_err(|error| AppError::internal(error.to_string()))?,
        pairing_code,
        new_device_pubkey: staged_public_key(record)?,
        client_nonce: DevicePairingNonce::new(record.client_nonce.clone())
            .map_err(|error| AppError::internal(error.to_string()))?,
        gate_audience_uri: record.gate_audience.clone(),
        server_nonce: DevicePairingNonce::new(record.server_nonce.clone())
            .map_err(|error| AppError::internal(error.to_string()))?,
        display_name: record
            .display_name
            .clone()
            .map(arkret_wire::NonEmptyString::new)
            .transpose()
            .map_err(|error| AppError::internal(error.to_string()))?,
        device_metadata: record
            .device_metadata
            .clone()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| AppError::internal(error.to_string()))?,
        expires_at: record.expires_at,
    })
}

fn pairing_lookup_failed(error: soland_services::ServiceError) -> AppError {
    AppError::internal(format!("device pairing lookup failed: {error}"))
}

fn device_pairing_not_found() -> AppError {
    AppError::not_found("device pairing request not found")
}
