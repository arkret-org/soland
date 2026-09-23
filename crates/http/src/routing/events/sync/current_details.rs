//! Realm detail delivery requires a committed, caller-authorized per-stream cut.
//!
//! The current storage page carries a signed snapshot and committed stream tails,
//! but it cannot yet prove the readable stream set or each stream's window-start
//! basis. A response that labels those rows complete would overstate coverage.

use arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame;

use super::*;

/// Reject a detail request until the same-cut current and per-stream window
/// provider is wired. Account-global channels remain available to clients
/// that did not request Realm details.
pub(super) async fn frame(
    _state: &AppState,
    session: Option<&SessionIdentityState>,
    body: &SyncRequestBody,
    after: &SyncCursor,
) -> Option<AccountSubscribeFrame> {
    let requested = body
        .filter
        .as_ref()
        .and_then(|filter| filter.realm_ids.as_ref())
        .is_some_and(|realms| !realms.is_empty());
    if !requested
        && !after.detail_turn
        && after.detail_positions.is_empty()
        && after.detail_next_realm.is_none()
    {
        return None;
    }

    let kind = if session.is_some() {
        tracing::warn!("Realm detail requires committed per-stream current and window coverage");
        "resync_required"
    } else {
        "unauthorized"
    };
    Some(serde_json::from_value(json!({"kind": kind})).expect("typed control frame"))
}
