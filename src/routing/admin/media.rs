//! Media admin aggregation endpoints.

use std::collections::BTreeMap;

use salvo::prelude::*;
use serde_json::{Value, json};

use super::{AuthArgs, append_audit_log, require_admin_principal};
use crate::state::{AppState, BlobRecord};
use crate::{JsonResult, json_ok};

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("media/statistics").get(get_media_statistics))
        .push(Router::with_path("media/by-actor").get(get_media_by_actor))
}

#[endpoint(
    operation_id = "org.cokret.soland.admin.media.statistics",
    tags("admin", "media"),
    summary = "Read aggregate media statistics"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.admin.media.statistics"))]
async fn get_media_statistics(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let session = require_admin_principal(state, session)?;
    let blobs = media_snapshot(state).await;
    let by_actor = media_by_actor_rows(state, &blobs).await;
    let mut by_media_type: BTreeMap<String, Value> = BTreeMap::new();
    let mut by_realm: BTreeMap<String, Value> = BTreeMap::new();
    let mut total_size = 0_u64;
    let mut encrypted_count = 0_u64;

    for blob in &blobs {
        let size = blob.size_bytes.max(0) as u64;
        total_size = total_size.saturating_add(size);
        if blob.encryption.is_some() {
            encrypted_count += 1;
        }
        add_bucket(&mut by_media_type, &blob.media_type, size);
        if let Some(realm_id) = blob.realm_id.as_deref() {
            add_bucket(&mut by_realm, realm_id, size);
        }
    }

    append_audit_log(
        state,
        Some(&session.actor),
        "admin.media.statistics",
        json!({
            "count": blobs.len(),
            "device_id": session.device_id,
        }),
        "accepted",
    )
    .await;

    json_ok(json!({
        "total_blobs": blobs.len() as u64,
        "total_count": blobs.len() as u64,
        "total_size": total_size,
        "total_size_bytes": total_size,
        "encrypted_count": encrypted_count,
        "quarantined_count": 0_u64,
        "by_media_type": by_media_type,
        "by_realm": by_realm,
        "by_actor": by_actor,
    }))
}

#[endpoint(
    operation_id = "org.cokret.soland.admin.media.by_actor",
    tags("admin", "media"),
    summary = "Read media usage grouped by actor"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.admin.media.by_actor"))]
async fn get_media_by_actor(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let session = require_admin_principal(state, session)?;
    let blobs = media_snapshot(state).await;
    let rows = media_by_actor_rows(state, &blobs).await;

    append_audit_log(
        state,
        Some(&session.actor),
        "admin.media.by_actor",
        json!({
            "actor_count": rows.len(),
            "device_id": session.device_id,
        }),
        "accepted",
    )
    .await;

    json_ok(json!({
        "resource": "media_by_actor",
        "data": rows,
        "items": rows,
        "actors": rows,
        "total": rows.len(),
        "next_cursor": null,
    }))
}

async fn media_snapshot(state: &AppState) -> Vec<BlobRecord> {
    state
        .persistence
        .blobs()
        .snapshot_all()
        .await
        .unwrap_or_default()
}

async fn media_by_actor_rows(state: &AppState, blobs: &[BlobRecord]) -> Vec<Value> {
    let accounts: BTreeMap<String, _> = state
        .persistence
        .accounts()
        .list()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|account| (account.did.clone(), account))
        .collect();
    let mut rows: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for blob in blobs {
        let size = blob.size_bytes.max(0) as u64;
        let entry = rows.entry(blob.uploaded_by.clone()).or_default();
        entry.0 += 1;
        entry.1 = entry.1.saturating_add(size);
    }
    rows.into_iter()
        .map(|(actor_id, (blob_count, total_size))| {
            let display_name = accounts
                .get(&actor_id)
                .and_then(|account| account.display_name.clone());
            json!({
                "actor_id": actor_id,
                "display_name": display_name,
                "blob_count": blob_count,
                "total_size": total_size,
                "total_size_bytes": total_size,
            })
        })
        .collect()
}

fn add_bucket(buckets: &mut BTreeMap<String, Value>, key: &str, size: u64) {
    let entry = buckets
        .entry(key.to_owned())
        .or_insert_with(|| json!({ "count": 0_u64, "size_bytes": 0_u64, "total_size": 0_u64 }));
    if let Some(object) = entry.as_object_mut() {
        let count = object.get("count").and_then(Value::as_u64).unwrap_or(0) + 1;
        let size_bytes = object
            .get("size_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            .saturating_add(size);
        object.insert("count".to_owned(), json!(count));
        object.insert("size_bytes".to_owned(), json!(size_bytes));
        object.insert("total_size".to_owned(), json!(size_bytes));
    }
}
