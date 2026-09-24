use super::*;
use crate::state::AppState;

const MAX_INLINE_REALM_STATE_SNAPSHOT_BYTES: usize = 8 * 1024 * 1024;

fn enforce_inline_snapshot_capacity<T: serde::Serialize>(
    snapshot: &T,
) -> Result<(), soland_http::error::AppError> {
    let canonical = arkret_canonical::canonical_json_bytes(snapshot)
        .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?;
    if canonical.len() > MAX_INLINE_REALM_STATE_SNAPSHOT_BYTES {
        return Err(crate::app_error!(
            PayloadTooLarge,
            "complete Realm State Snapshot exceeds the 8 MiB inline response limit",
        )
        .with_wire_code("payload_too_large"));
    }
    Ok(())
}

/// Build the one closed, inline v1 snapshot from a single durable-cut
/// materialization. No chunk, cursor, or partial fallback exists.
pub(crate) async fn realm_state_snapshot_manifest_for_realm(
    state: &AppState,
    realm_id: &str,
    account: &arkret_wire::AccountId,
) -> Result<arkret_wire::RealmStateSnapshot, soland_http::error::AppError> {
    let realm_id = arkret_wire::RealmId::new(realm_id.to_owned())
        .map_err(|_| soland_http::error::AppError::param_invalid("invalid realm_id"))?;
    let material = state
        .authority_commits()
        .realm_state_snapshot_material_for_account(&realm_id, account)
        .await
        .map_err(|error| {
            tracing::warn!(%error, realm_id=%realm_id, "snapshot disclosure gate rejected material");
            crate::app_error!(
                RealmStateSnapshotUnavailable,
                "complete Account disclosure cannot be proved at this cut",
            )
        })?
        .ok_or_else(|| soland_http::error::AppError::not_found("not found"))?;
    let authority = state
        .authority_commits()
        .current_authority(&realm_id)
        .await
        .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?
        .ok_or_else(|| soland_http::error::AppError::not_found("not found"))?;
    if authority.generation != material.governance_generation
        || authority.service_id != state.service_core_id()
    {
        return Err(crate::app_error!(
            RealmStateSnapshotUnavailable,
            "the current governance Station cannot sign this Realm snapshot",
        ));
    }
    let verification_method = state
        .service_verification_method("notary-key")
        .map_err(soland_http::error::AppError::internal)?;
    let snapshot = soland_services::authority_commit::build_signed_realm_state_snapshot(
        &material,
        verification_method,
        state.notary_signing_key().as_ref(),
        crate::wire::now(),
    )
    .map_err(|error| soland_http::error::AppError::internal(error.to_string()))?;
    enforce_inline_snapshot_capacity(&snapshot)?;
    Ok(snapshot)
}

pub(crate) fn generate_invite_token(invite_id: &str, realm_id: &str, invitee_id: &str) -> String {
    format!(
        "ak:invite-token:{}",
        sha256_hex(format!("{invite_id}:{realm_id}:{invitee_id}").as_bytes())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_snapshot_capacity_rejects_the_complete_oversized_body() {
        enforce_inline_snapshot_capacity(&serde_json::json!({"payload": "x"})).unwrap();
        let oversized = serde_json::json!({
            "payload": "x".repeat(MAX_INLINE_REALM_STATE_SNAPSHOT_BYTES),
        });
        let error = enforce_inline_snapshot_capacity(&oversized).unwrap_err();
        assert_eq!(error.wire_code(), "payload_too_large");
    }
}
