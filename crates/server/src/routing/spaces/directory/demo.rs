use super::*;

/// Snapshot the in-memory realm directory (under a short lock) and return the
/// owned entries that are not tombstoned. The deleted check is async (it reads
/// `realm_meta`), so we must not run it while holding the `realms` lock — we
/// collect candidates first, drop the guard, then filter with `.await`.
pub(super) async fn live_realm_entries(state: &AppState) -> Vec<RealmDirectoryEntry> {
    let candidates: Vec<RealmDirectoryEntry> = {
        let realms = state.realms.lock().expect("realms lock");
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

pub fn demo_organization(realms: &[&RealmDirectoryEntry], service_did: &str) -> Value {
    json!({
        "organization_id": "ck:org:demo",
        "organization_did": service_did,
        "handle": "@cokret-demo",
        "name": "Cokret Demo Organization",
        "description": "Demo organization projected by soland",
        "service_did": service_did,
        "realm_count": realms.len(),
        "actor_count": 1,
    })
}

pub async fn demo_actors(state: &AppState) -> Vec<Value> {
    let mut actors = vec![json!({
        "did": "did:web:alice.example",
        "handle": "@alice",
        "display_name": "Alice Example",
        "organization_id": "ck:org:demo",
        "avatar_url": null,
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
        actors.push(json!({
            "did": account.did,
            "handle": account.handle(),
            "display_name": account.display_name.as_deref().unwrap_or(account.did.as_str()),
            "state": account_state.clone(),
            "account_state": account_state,
            "bio": account.bio,
            "organization_id": "ck:org:demo",
            "avatar_url": account.avatar_url,
            "presence": {"status": "offline", "updated_at": now()},
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
        actors.push(json!({
            "did": did,
            "handle": handle_for_did(did),
            "display_name": display_name,
            "state": account_state.clone(),
            "account_state": account_state,
            "organization_id": "ck:org:demo",
            "avatar_url": null,
            "presence": {"status": "offline", "updated_at": now()},
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
