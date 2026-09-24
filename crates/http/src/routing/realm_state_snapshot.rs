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
    if error.conflict_code() == Some(soland_storage::ConflictCode::TemporarilyUnavailable) {
        // A handoff committed while this cut held its share lock: nothing
        // was signed or archived, and the caller may retry the exact read.
        tracing::info!(%error, realm_id=%realm_id, "snapshot issuance lost a governing-cut race");
        return snapshot_unavailable("the governing cut changed during snapshot issuance");
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

#[cfg(test)]
mod issue_error_tests {
    use super::*;

    fn realm() -> arkret_wire::RealmId {
        arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x5a; 32],
        ))
    }

    #[test]
    fn concurrent_handoff_race_is_the_registered_snapshot_unavailability() {
        let raced = map_issue_error(
            &realm(),
            soland_services::ServiceError::Conflict(format!(
                "{}: the governing cut changed concurrently: could not serialize access",
                soland_storage::ConflictCode::TemporarilyUnavailable.as_str(),
            )),
        );
        assert_eq!(raced.wire_code(), "realm_state_snapshot_unavailable");
        assert_eq!(raced.http_status().as_u16(), 503);

        // An unclassified storage fault stays internal rather than being
        // guessed into a caller-facing reason.
        let fault = map_issue_error(
            &realm(),
            soland_services::ServiceError::Database("connection reset".to_owned()),
        );
        assert_eq!(fault.http_status().as_u16(), 500);
    }
}
