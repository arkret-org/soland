use super::*;

/// Snapshot the in-memory realm directory (under a short lock) and return the
/// owned entries that are not tombstoned. The deleted check is async (it reads
/// `realm_meta`), so we must not run it while holding the `realms` lock — we
/// collect candidates first, drop the guard, then filter with `.await`.
pub(super) async fn live_realm_entries(state: &AppState) -> Vec<RealmDirectoryEntry> {
    let candidates: Vec<RealmDirectoryEntry> = {
        let realms = state.realm_directory().snapshot();
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
    if state.config().development_mode {
        return Ok(());
    }
    Err(AppError::not_found("directory provider not configured"))
}

pub fn demo_organization(realms: &[&RealmDirectoryEntry], service_id: &str) -> Value {
    json!({
        "organization_id": service_id,
        "organization_principal_id": service_id,
        "handle": "@arkret-demo",
        "title": "Arkret Demo Organization",
        "display_name": "Arkret Demo Organization",
        "description": "Demo organization projected by soland",
        "source_refs": ["ak:event:AbyMki5ktjJoPFPuzhe-f4rb2rhjWdtfyMrbjIdb4qsO"],
        "policy_revision": "local",
        "service_id": service_id,
        "realm_count": realms.len(),
        "actor_count": 1,
    })
}

pub async fn demo_actors(state: &AppState) -> Vec<Value> {
    let mut actors = vec![json!({
        "actor_id": "ak:did_core:web:alice.example",
        "handle": "@alice",
        "display_name": "Alice Example",
        "organization_id": state.service_id(),
        "avatar_blob_ref": null,
    })];

    let accounts = state.identities().accounts().await.unwrap_or_default();
    for account in accounts {
        if actors
            .iter()
            .any(|actor| actor["actor_id"].as_str() == Some(account.principal_id.as_str()))
        {
            continue;
        }
        let account_state = state.account_lifecycle_state(account.principal_id.as_str());
        // GDPR erasure / deactivation: terminal account states MUST NOT
        // surface in directory search results.
        if matches!(account_state.as_str(), "deactivated" | "erasure_pending") {
            continue;
        }
        let profile = crate::routing::identity::account::accepted_account_profile(
            state,
            account.principal_id.as_str(),
        )
        .await
        .ok()
        .flatten();
        let display_name = profile
            .as_ref()
            .map(|profile| profile.display_name.clone())
            .unwrap_or_else(|| account.principal_id.to_string());
        let bio = profile
            .as_ref()
            .and_then(|profile| profile.profile_fields.get("bio"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let avatar_blob_ref = profile
            .as_ref()
            .and_then(|profile| profile.avatar_blob_ref.clone());
        actors.push(json!({
            "actor_id": account.principal_id,
            "handle": account.handle(),
            "display_name": display_name,
            "state": account_state.clone(),
            "account_state": account_state,
            "bio": bio,
            "organization_id": state.service_id(),
            "avatar_blob_ref": avatar_blob_ref,
        }));
    }

    let devices = state
        .identities()
        .devices()
        .await
        .map(|devices| {
            let mut grouped: BTreeMap<String, BTreeMap<String, Value>> = BTreeMap::new();
            for device in devices {
                grouped
                    .entry(device.actor_id.clone())
                    .or_default()
                    .insert(device.device_id.clone(), device_inventory_to_json(&device));
            }
            grouped
        })
        .unwrap_or_default();
    for (actor_id, actor_devices) in devices.iter() {
        let account_state = state.account_lifecycle_state(actor_id);
        if matches!(account_state.as_str(), "deactivated" | "erasure_pending") {
            continue;
        }
        if actors.iter().any(|actor| {
            actor["actor_id"]
                .as_str()
                .is_some_and(|known| known == actor_id)
        }) {
            continue;
        }
        let display_name = actor_devices
            .values()
            .find_map(|device| device["display_name"].as_str())
            .unwrap_or(actor_id);
        actors.push(json!({
            "actor_id": actor_id,
            "handle": handle_for_did(actor_id),
            "display_name": display_name,
            "state": account_state.clone(),
            "account_state": account_state,
            "organization_id": state.service_id(),
            "avatar_blob_ref": null,
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
        return Err(AppError::param_invalid("limit must be between 1 and 100"));
    }
    Ok(limit)
}
