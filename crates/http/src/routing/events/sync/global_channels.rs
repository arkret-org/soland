use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountDataContainer, StationCasAccountDataContainer, StationCasAccountDataRemoval,
};
use arkret_models_collaboration::sync_frames::account_sync::{
    AccountSubscribeDeviceListChanges, NotificationContainer,
};
use arkret_models_collaboration::sync_frames::demand_sync::{
    AccountBaselineChannel, AccountBaselineSegment,
};

use super::*;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GlobalProgress {
    snapshot_cursor: arkret_wire::Cursor,
    snapshot_watermark: i64,
    snapshot_expires_at_ms: i64,
    offsets: BTreeMap<String, String>,
    completed: BTreeSet<String>,
    positions: BTreeMap<String, i64>,
}

pub(crate) struct GlobalDelta {
    pub context: Value,
    pub baseline: Option<AccountBaselineSegment>,
    pub account_data: AccountDataContainer,
    pub notifications: NotificationContainer,
    pub device_lists: AccountSubscribeDeviceListChanges,
}

pub(crate) async fn read(
    state: &AppState,
    session: &SessionIdentityState,
    after: &SyncCursor,
    initial_snapshot: Option<(i64, i64)>,
) -> Result<GlobalDelta, String> {
    let actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, session)
            .map_err(|_| "invalid account actor".to_owned())?;
    let actor_key = actor.canonical_key().map_err(|error| error.to_string())?;
    let watermark = state
        .sync()
        .account_global_watermark()
        .await
        .map_err(|error| error.to_string())?;
    let mut progress = if let Some(context) = &after.global_baseline {
        serde_json::from_value::<GlobalProgress>(context.clone())
            .map_err(|error| error.to_string())?
    } else {
        GlobalProgress {
            snapshot_cursor: arkret_wire::Cursor::new(format!(
                "ak:cursor:{}",
                uuid::Uuid::now_v7().simple()
            ))
            .map_err(|error| error.to_string())?,
            snapshot_watermark: initial_snapshot.map_or(watermark, |(cut, _)| cut),
            snapshot_expires_at_ms: initial_snapshot.map_or_else(
                || chrono::Utc::now().timestamp_millis() + 3_600_000,
                |(_, deadline)| deadline,
            ),
            offsets: BTreeMap::new(),
            completed: BTreeSet::new(),
            positions: BTreeMap::new(),
        }
    };
    if progress.completed.len() < 4
        && progress.snapshot_expires_at_ms <= chrono::Utc::now().timestamp_millis()
    {
        return Err("account baseline snapshot expired; establish a fresh baseline".into());
    }
    let mut account_data = AccountDataContainer::default();
    let mut cas = StationCasAccountDataContainer::default();
    let mut notifications = NotificationContainer::default();
    let mut device_lists = AccountSubscribeDeviceListChanges {
        changed_ids: Vec::new(),
        left_ids: Vec::new(),
    };
    let mut channels = Vec::new();
    let mut completed_channels = Vec::new();
    let mut remaining_bytes = 6 * 1024 * 1024;
    for (name, channel) in [
        (
            "account_data_events",
            AccountBaselineChannel::AccountDataEvents,
        ),
        ("station_cas", AccountBaselineChannel::StationCas),
        ("notifications", AccountBaselineChannel::Notifications),
        ("device_lists", AccountBaselineChannel::DeviceLists),
    ] {
        let baseline = !progress.completed.contains(name);
        let cut = if baseline {
            progress.snapshot_watermark
        } else {
            watermark
        };
        let position = progress
            .positions
            .get(name)
            .copied()
            .unwrap_or(progress.snapshot_watermark);
        let offset = progress.offsets.get(name).cloned().unwrap_or_default();
        let rows = state
            .sync()
            .account_global_page(
                &actor_key,
                name,
                cut,
                &offset,
                (!baseline).then_some(position),
                101,
            )
            .await
            .map_err(|error| error.to_string())?;
        let mut consumed = 0usize;
        let mut by_key = BTreeMap::new();
        for row in &rows {
            if row.payload.get("_oversized").and_then(Value::as_bool) == Some(true) {
                return Err("one account-global value exceeds the byte budget".to_owned());
            }
            if row.payload.get("_budget_boundary").is_some() {
                break;
            }
            if consumed >= 100 {
                break;
            }
            let bytes = arkret_canonical::canonical_json_bytes(&row.payload)
                .map_err(|error| error.to_string())?
                .len()
                + 256;
            if bytes > remaining_bytes {
                if consumed == 0 && remaining_bytes == 6 * 1024 * 1024 {
                    return Err("account global item exceeds frame byte budget".to_owned());
                }
                break;
            }
            remaining_bytes -= bytes;
            consumed += 1;
            if baseline {
                progress
                    .offsets
                    .insert(name.to_owned(), row.item_key.clone());
            } else {
                progress.positions.insert(name.to_owned(), row.revision);
            }
            by_key.insert(row.item_key.clone(), row);
        }
        if baseline {
            channels.push(channel);
            if consumed == rows.len() && rows.len() < 101 {
                progress.completed.insert(name.to_owned());
                progress.positions.insert(name.to_owned(), cut);
                progress.offsets.remove(name);
                completed_channels.push(channel);
            }
        } else if consumed == rows.len() && rows.len() < 101 {
            progress.positions.insert(name.to_owned(), cut);
        }
        for row in by_key.into_values() {
            if baseline && row.deleted {
                continue;
            }
            match name {
                "account_data_events" => {
                    if row.payload["source"] == "invalidated" {
                        return Err(
                            "account data source was withdrawn; establish a fresh baseline"
                                .to_owned(),
                        );
                    }
                    let event: arkret_wire::Event =
                        serde_json::from_value(row.payload["value"].clone())
                            .map_err(|error| error.to_string())?;
                    let key = event
                        .payload
                        .get("key")
                        .and_then(Value::as_str)
                        .ok_or("account data key absent")?;
                    if event.actor_id!=actor || crate::routing::identity::account_data::is_service_internal_account_data_key(key) || (session.agent_session.is_some() && crate::routing::identity::account_data::is_controller_private_account_data_key(key)) {continue;}
                    account_data.events.push(event);
                }

                "station_cas" => {
                    let key = row.payload["account_data_key"]
                        .as_str()
                        .ok_or("CAS key absent")?;
                    if !crate::routing::identity::account_data::is_station_cas_account_data_key(key)
                    {
                        continue;
                    }
                    let revision = row.payload["revision"]
                        .as_u64()
                        .ok_or("CAS revision absent")?;
                    let updated_at = serde_json::from_value(row.payload["updated_at"].clone())
                        .map_err(|error| error.to_string())?;
                    if row.deleted {
                        cas.removals.push(StationCasAccountDataRemoval {
                            account_data_key: key.to_owned(),
                            revision,
                            updated_at,
                        });
                    } else {
                        cas.upserts
                            .push(arkret_models_identity::account::AccountDataRow {
                                account_data_key: key.to_owned(),
                                revision,
                                content: row.payload["payload"].clone(),
                                updated_at,
                            });
                    }
                }
                "notifications" => notifications.items.push(
                    serde_json::from_value(row.payload.clone())
                        .map_err(|error| error.to_string())?,
                ),
                "device_lists" => {
                    let owner = serde_json::from_value(row.payload.clone())
                        .map_err(|error| error.to_string())?;
                    if row.deleted {
                        device_lists.left_ids.push(owner);
                    } else {
                        device_lists.changed_ids.push(owner);
                    }
                }
                _ => unreachable!(),
            }
        }
    }
    if !cas.upserts.is_empty()
        || !cas.removals.is_empty()
        || channels.contains(&AccountBaselineChannel::StationCas)
    {
        account_data.station_cas = Some(cas);
    }
    let baseline = (!channels.is_empty()).then(|| AccountBaselineSegment {
        snapshot_cursor: progress.snapshot_cursor.clone(),
        channels,
        completed_channels,
    });
    Ok(GlobalDelta {
        context: serde_json::to_value(progress).map_err(|error| error.to_string())?,
        baseline,
        account_data,
        notifications,
        device_lists,
    })
}
