//! Direct identity ownership uses native history, never a PCR device key.
use arkret_identity::principal_control::{DirectIdentityControlPurpose, NativeIdentityControlKey};
use arkret_wire::{Did, DidCoreId, DidUrl};

use crate::state::AppState;

pub(crate) async fn resolve_native_identity_control(
    state: &AppState,
    principal_did: &Did,
    expected_core: &DidCoreId,
    method: &DidUrl,
    at: chrono::DateTime<chrono::Utc>,
    purpose: DirectIdentityControlPurpose,
) -> Result<
    (
        NativeIdentityControlKey,
        soland_services::identity::PinnedDidDocumentState,
    ),
    String,
> {
    if arkret_wire::project_did_to_core_id(principal_did).map_err(|e| e.to_string())?
        != *expected_core
    {
        return Err("identity locator does not bind expected principal".to_owned());
    }
    let selected = state
        .dids()
        .resolve_webvh_state_at(principal_did, at)
        .await
        .map_err(|e| e.to_string())?;
    let key =
        arkret_identity::principal_control::native_identity_control_key_from_verified_selection(
            &selected.did,
            expected_core,
            &selected.update_keys,
            method,
            purpose,
        )
        .map_err(|e| e.to_string())?;
    Ok((key, selected))
}
