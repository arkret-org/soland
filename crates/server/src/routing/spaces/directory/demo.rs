use super::*;

/// Snapshot the in-memory realm directory (under a short lock) and return the
/// owned entries that are not tombstoned. The deleted check is async (it reads
/// `realm_meta`), so we must not run it while holding the `realms` lock — we
/// collect candidates first, drop the guard, then filter with `.await`.
pub(super) async fn live_realm_entries(state: &AppState) -> Vec<RealmDirectoryEntry> {
    let candidates: Vec<RealmDirectoryEntry> = {
        let realms = state.realms.lock();
        realms
            .search(Default::default())
            .into_iter()
            .cloned()
            .collect()
    };
    let mut live = Vec::new();
    for realm_entry in candidates {
        if !is_realm_deleted(state, realm_entry.realm_id.as_str()).await {
            live.push(realm_entry);
        }
    }
    live
}

pub(super) fn require_demo_directory_provider(state: &AppState) -> Result<(), AppError> {
    if state.config.development_mode {
        return Ok(());
    }
    Err(AppError::not_found("directory provider not configured"))
}

pub fn demo_organization(realms: &[&RealmDirectoryEntry], service_id: &str) -> Value {
    json!({
        "organization_id": "ak:org:demo",
        "organization_did": service_id,
        "handle": "@arkret-demo",
        "title": "Arkret Demo Organization",
        "display_name": "Arkret Demo Organization",
        "description": "Demo organization projected by soland",
        "source_refs": ["ak:event:0196419b-0000-7000-8000-0000000000d0"],
        "policy_revision": "local",
        "service_id": service_id,
        "realm_count": realms.len(),
        "actor_count": 1,
    })
}

/// Project the live presence store value for `actor` into the directory
/// preview shape. Uses the shared multi-device aggregation
/// (profiles-presence.md §3.3): unexpired device rows merge by priority
/// and a fully-lapsed actor projects as `offline`. Absent records
/// project as `offline`.
pub(super) async fn directory_presence_for_actor(state: &AppState, did: &str) -> Value {
    let records = state
        .persistence
        .presence()
        .list_for_actor(did)
        .await
        .unwrap_or_default();
    let (status, updated_at) =
        match crate::routing::events::sync::aggregate_presence_records(&records, now()) {
            Some(aggregated) => (aggregated.status, aggregated.updated_at),
            None => ("offline".to_owned(), now()),
        };
    json!({ "status": status, "updated_at": updated_at })
}

pub async fn demo_actors(state: &AppState) -> Vec<Value> {
    let mut actors = vec![json!({
        "did": "did:web:alice.example",
        "handle": "@alice",
        "display_name": "Alice Example",
        "organization_id": "ak:org:demo",
        "avatar_blob_ref": null,
        "presence": {"status": "online", "updated_at": now()},
    })];

    let accounts = state
        .persistence
        .accounts()
        .list()
        .await
        .unwrap_or_default();
    for account in accounts {
        if actors
            .iter()
            .any(|actor| actor["did"].as_str() == Some(account.did.as_str()))
        {
            continue;
        }
        let account_state = state.account_lifecycle_state(&account.did);
        // GDPR erasure / deactivation: terminal account states MUST NOT
        // surface in directory search results.
        if matches!(account_state.as_str(), "deactivated" | "erasure_pending") {
            continue;
        }
        let presence = directory_presence_for_actor(state, &account.did).await;
        actors.push(json!({
            "did": account.did,
            "handle": account.handle(),
            "display_name": account.display_name.as_deref().unwrap_or(account.did.as_str()),
            "state": account_state.clone(),
            "account_state": account_state,
            "bio": account.bio,
            "organization_id": "ak:org:demo",
            "avatar_blob_ref": account.avatar_blob_ref,
            "presence": presence,
        }));
    }

    let devices = state
        .persistence
        .devices()
        .list()
        .await
        .map(|devices| {
            let mut grouped: BTreeMap<String, BTreeMap<String, Value>> = BTreeMap::new();
            for device in devices {
                grouped
                    .entry(device.actor.clone())
                    .or_default()
                    .insert(device.device_id.clone(), device_inventory_to_json(&device));
            }
            grouped
        })
        .unwrap_or_default();
    for (did, actor_devices) in devices.iter() {
        let account_state = state.account_lifecycle_state(did);
        if matches!(account_state.as_str(), "deactivated" | "erasure_pending") {
            continue;
        }
        if actors
            .iter()
            .any(|actor| actor["did"].as_str().is_some_and(|known| known == did))
        {
            continue;
        }
        let display_name = actor_devices
            .values()
            .find_map(|device| device["display_name"].as_str())
            .unwrap_or(did);
        let presence = directory_presence_for_actor(state, did).await;
        actors.push(json!({
            "did": did,
            "handle": handle_for_did(did),
            "display_name": display_name,
            "state": account_state.clone(),
            "account_state": account_state,
            "organization_id": "ak:org:demo",
            "avatar_blob_ref": null,
            "presence": presence,
        }));
    }
    actors
}

pub fn query_matches(value: &Value, query: Option<&str>) -> bool {
    let Some(query) = query.map(str::trim).filter(|query| !query.is_empty()) else {
        return true;
    };
    value
        .to_string()
        .to_ascii_lowercase()
        .contains(&query.to_ascii_lowercase())
}

pub fn checked_limit(limit: Option<usize>) -> Result<usize, AppError> {
    let limit = limit.unwrap_or(20);
    if !(1..=100).contains(&limit) {
        return Err(AppError::invalid_param("limit must be between 1 and 100"));
    }
    Ok(limit)
}
