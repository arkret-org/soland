//! Shared lock order for artifacts addressed to more than one device.
use super::*;

/// Acquire every involved account/device lock before any artifact row lock.
/// Distinct authorization instances for the same device are not deduplicated:
/// each original selector must pass the final current-instance check.
pub(crate) async fn lock_artifact_devices_in_transaction(
    conn: &mut AsyncPgConnection,
    selectors: &[&DeviceRevocationGateSelector],
) -> PersistenceResult<()> {
    let mut ordered = selectors.to_vec();
    ordered.sort_by(|a, b| {
        (&a.principal_id, &a.station_id, &a.device_id).cmp(&(
            &b.principal_id,
            &b.station_id,
            &b.device_id,
        ))
    });
    for selector in &ordered {
        ensure_head_locked(
            conn,
            selector.principal_id.as_str(),
            selector.station_id.as_str(),
            &selector.device_id,
        )
        .await?;
    }
    Ok(())
}
