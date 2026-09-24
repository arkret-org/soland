use super::*;
use crate::state::AppState;

fn snapshot_unavailable(message: &'static str) -> soland_http::error::AppError {
    crate::app_error!(RealmStateSnapshotUnavailable, message,)
}

fn map_issue_error(
    realm_id: &arkret_wire::RealmId,
    error: soland_services::ServiceError,
) -> soland_http::error::AppError {
    if error.conflict_code() == Some(soland_storage::ConflictCode::SnapshotCapacityExceeded) {
        return crate::app_error!(
            PayloadTooLarge,
            "complete Realm State Snapshot exceeds the 8 MiB inline response limit",
        )
        .with_wire_code("payload_too_large");
    }
    match error {
        soland_services::ServiceError::SchemaViolation(_) => {
            tracing::warn!(%error, realm_id=%realm_id, "snapshot disclosure gate rejected material");
            snapshot_unavailable("complete Account disclosure cannot be proved at this cut")
        }
        other => soland_http::error::AppError::internal(other.to_string()),
    }
}

/// Issue the one closed, inline v1 snapshot from a single durable cut that
/// also proves this Station's current governing tenure and persists the exact
/// signed object for later by-ref reads. No chunk, cursor, or partial
/// fallback exists.
pub(crate) async fn realm_state_snapshot_manifest_for_realm(
    state: &AppState,
    realm_id: &str,
    account: &arkret_wire::AccountId,
) -> Result<arkret_wire::RealmStateSnapshot, soland_http::error::AppError> {
    let realm_id = arkret_wire::RealmId::new(realm_id.to_owned())
        .map_err(|_| soland_http::error::AppError::param_invalid("invalid realm_id"))?;
    let verification_method = state
        .service_verification_method("notary-key")
        .map_err(soland_http::error::AppError::internal)?;
    let signing_key = state.notary_signing_key();
    state
        .authority_commits()
        .issue_realm_state_snapshot_for_account(
            &realm_id,
            account,
            &state.service_core_id(),
            &verification_method,
            signing_key.as_ref(),
            crate::wire::now(),
        )
        .await
        .map_err(|error| map_issue_error(&realm_id, error))?
        .ok_or_else(|| soland_http::error::AppError::not_found("not found"))
}

/// Return exactly the original object previously issued to this Account,
/// after the store re-proves its disclosure at the read cut. A missing or no
/// longer disclosable reference is unavailable; `/head` never substitutes.
pub(crate) async fn issued_realm_state_snapshot_for_account(
    state: &AppState,
    realm_id: &str,
    snapshot_id: &arkret_wire::RealmSnapshotId,
    account: &arkret_wire::AccountId,
) -> Result<arkret_wire::RealmStateSnapshot, soland_http::error::AppError> {
    let realm_id = arkret_wire::RealmId::new(realm_id.to_owned())
        .map_err(|_| soland_http::error::AppError::param_invalid("invalid realm_id"))?;
    match state
        .authority_commits()
        .issued_realm_state_snapshot(&realm_id, account, snapshot_id, &state.service_core_id())
        .await
    {
        Ok(Some(snapshot)) => Ok(snapshot),
        Ok(None) => Err(snapshot_unavailable(
            "the exact snapshot was not issued to this Account",
        )),
        Err(soland_services::ServiceError::SchemaViolation(reason)) => {
            tracing::warn!(%reason, realm_id=%realm_id, "issued snapshot disclosure recheck failed");
            Err(snapshot_unavailable(
                "the exact snapshot is no longer safely disclosable",
            ))
        }
        Err(error) => Err(soland_http::error::AppError::internal(error.to_string())),
    }
}

pub(crate) fn generate_invite_token(invite_id: &str, realm_id: &str, invitee_id: &str) -> String {
    format!(
        "ak:invite-token:{}",
        sha256_hex(format!("{invite_id}:{realm_id}:{invitee_id}").as_bytes())
    )
}
