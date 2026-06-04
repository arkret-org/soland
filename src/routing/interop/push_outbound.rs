//! Outbound push gateway bridge — describe / resolve / fetch / cache.
//!
//! Surfaces:
//! - `GET  /_soland/edge/push/outbound/bridge/describe`        — manifest
//! - `POST /_soland/edge/push/outbound/bridge/resolve`         — resolve gateway URL → contract
//! - `POST /_soland/edge/push/outbound/bridge/fetch`           — pull remote contract + cache
//! - `GET  /_soland/edge/push/outbound/bridge/cache/status`    — current cache age
//! - `GET  /_soland/edge/push/outbound/bridge/cache/export`    — dump cache snapshots
//! - `POST /_soland/edge/push/outbound/bridge/cache/import`    — restore snapshots
//! - `POST /_soland/edge/push/outbound/bridge/cache/invalidate`— invalidate one entry
//!
//! Implemented: live remote `bridge/describe` fetch with `Etag`/freshness
//! metadata stamped per entry; durable cache via
//! `state.persistence.push_bridge_cache()` (PostgreSQL when configured,
//! in-memory when not); contract-digest drift fails closed unless the caller
//! sets `force_refresh=true`; snapshot export/import round-trips trust
//! level + freshness alongside the contract digest.
//!
//! Trust + freshness:
//! - **TTL freshness**: cache_hit reads check `freshness_at + push_bridge_cache_ttl_seconds`
//!   (default 900s). Stale entries are downgraded to `trust_level=stale` and surface
//!   `fetch_state=cache_hit_stale`, so downstream `ck.push.notify` never delivers off a stale
//!   snapshot without an explicit operator action (force_refresh on /fetch, or import).
//! - **Signed-service-DID trust**: snapshot imports / live fetches only promote
//!   `trust_level=trusted` when the upstream contract's `service_did` matches
//!   `AppConfig::push_bridge_trusted_service_dids` (or `development_mode=true`). Everything else
//!   lands at `trust_level=pending` and outbound delivery treats it as unsigned-only.
//! - **Auth modes / privacy descriptors**: `OutboundPushResolvedContract` surfaces the upstream
//!   `auth_modes[]` and `privacy.*` fields so the delivery layer can bind outbound signing to
//!   whatever the gateway advertised (instead of the fixed `ck.push.notify` defaults). Stays
//!   read-only here — the actual binding lives in the delivery loop.

use std::time::Duration;

use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{now, sha256_hex};
use crate::error::AppError;
use crate::result::{JsonResult, json_ok};
use crate::state::{AppState, OutboundPushBridgeCacheRecord};
use crate::wire::{
    OutboundPushBridgeCacheEntry, OutboundPushBridgeCacheExportResponse,
    OutboundPushBridgeCacheImportRequest, OutboundPushBridgeCacheImportResponse,
    OutboundPushBridgeCacheInvalidateRequest, OutboundPushBridgeCacheInvalidateResponse,
    OutboundPushBridgeCacheSnapshot, OutboundPushBridgeCacheStatusResponse,
    OutboundPushBridgeDescribeResponse, OutboundPushBridgeExamples, OutboundPushBridgeFetchRequest,
    OutboundPushBridgeFetchResponse, OutboundPushBridgeResolveRequest,
    OutboundPushBridgeResolveResponse, OutboundPushDeliveryDescriptor,
    OutboundPushGatewayContractDescriptor, OutboundPushResolvedContract,
};

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("push/outbound/bridge/describe").get(outbound_push_bridge_describe))
        .push(Router::with_path("push/outbound/bridge/resolve").post(outbound_push_bridge_resolve))
        .push(Router::with_path("push/outbound/bridge/fetch").post(outbound_push_bridge_fetch))
        .push(
            Router::with_path("push/outbound/bridge/cache/status")
                .get(outbound_push_bridge_cache_status),
        )
        .push(
            Router::with_path("push/outbound/bridge/cache/export")
                .get(outbound_push_bridge_cache_export),
        )
        .push(
            Router::with_path("push/outbound/bridge/cache/import")
                .post(outbound_push_bridge_cache_import),
        )
        .push(
            Router::with_path("push/outbound/bridge/cache/invalidate")
                .post(outbound_push_bridge_cache_invalidate),
        )
}

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "outbound_push_bridge_describe"))]
async fn outbound_push_bridge_describe(depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    res.render(Json(OutboundPushBridgeDescribeResponse {
        contract: "cokret.rest.outbound_push_bridge.v1".to_owned(),
        version: "2026-05-04-scaffold".to_owned(),
        api_base_path: "/_soland/edge/push".to_owned(),
        gateway_contract: OutboundPushGatewayContractDescriptor {
            resolve_path: "/_soland/edge/push/outbound/bridge/resolve".to_owned(),
            fetch_path: "/_soland/edge/push/outbound/bridge/fetch".to_owned(),
            cache_status_path: "/_soland/edge/push/outbound/bridge/cache/status".to_owned(),
            cache_invalidate_path: "/_soland/edge/push/outbound/bridge/cache/invalidate"
                .to_owned(),
            cache_export_path: "/_soland/edge/push/outbound/bridge/cache/export"
                .to_owned(),
            cache_import_path: "/_soland/edge/push/outbound/bridge/cache/import"
                .to_owned(),
            bridge_describe_path: "/_cokret/edge/push/bridge/describe".to_owned(),
            notify_path: "/_cokret/edge/push/notify".to_owned(),
            accepted_contracts: vec![
                "ck.push.bridge.describe".to_owned(),
                "ck.profile.push_gateway.v1".to_owned(),
            ],
            fetch_mode: "live_http_fetch_with_durable_cache_fallback".to_owned(),
            cache_mode: "durable_snapshot_cache_with_drift_check".to_owned(),
            snapshot_store_mode: "durable_export_import_with_freshness_and_trust_level".to_owned(),
        },
        delivery: OutboundPushDeliveryDescriptor {
            operation_id: "ck.push.notify".to_owned(),
            origin_service_did_header: "X-Cokret-Origin-Service-Did".to_owned(),
            destination_service_did_header: "X-Cokret-Destination-Service-Did".to_owned(),
            request_id_header: "X-Cokret-Request-Id".to_owned(),
            idempotency_key_header: "Idempotency-Key".to_owned(),
            payload_mode: format!(
                "blind_wakeup_from_principal_service_did={}",
                state.config.service_did
            ),
        },
        examples: OutboundPushBridgeExamples {
            resolve_request: json!({
                "push_gateway_url": "https://floria.example/_cokret/edge/push/notify",
                "refresh": false
            }),
            fetch_request: json!({
                "push_gateway_url": "https://floria.example/_cokret/edge/push/notify",
                "force_refresh": true
            }),
            notify_headers: json!({
                "X-Cokret-Origin-Service-Did": state.config.service_did,
                "X-Cokret-Destination-Service-Did": "did:web:floria.example",
                "X-Cokret-Request-Id": "req_01js0000000000000000000000",
                "Idempotency-Key": "notify-01js0000000000000000000000"
            }),
            cache_import_request: json!({
                "replace_existing": true,
                "entries": [{
                    "push_gateway_url": "https://floria.example/_cokret/edge/push/notify",
                    "service_base_url": "https://floria.example",
                    "bridge_describe_url": "https://floria.example/_cokret/edge/push/bridge/describe",
                    "fetch_state": "seed_import",
                    "cache_state": "imported_replace_existing",
                    "contract_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                    "fetched_at": now(),
                    "remote_contract": {
                        "contract": "ck.push.bridge.describe",
                        "delivery": {
                            "notify_path": "/_cokret/edge/push/notify",
                            "operation_id": "ck.push.notify"
                        }
                    }
                }]
            }),
            cache_export_response: json!({
                "entries": [{
                    "push_gateway_url": "https://floria.example/_cokret/edge/push/notify",
                    "service_base_url": "https://floria.example",
                    "bridge_describe_url": "https://floria.example/_cokret/edge/push/bridge/describe",
                    "fetch_state": "cache_hit",
                    "cache_state": "memory_cached",
                    "contract_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                    "remote_contract": {
                        "contract": "ck.push.bridge.describe"
                    }
                }],
                "snapshot_store_kind": "durable_push_bridge_cache"
            }),
        },
        todos: Vec::new(),
    }));
}

#[endpoint(
    operation_id = "ck.extension.soland.push.outbound_bridge_resolve",
    tags("push"),
    summary = "Resolve a push gateway URL to a cached contract snapshot"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ck.extension.soland.push.outbound_bridge_resolve")
)]
async fn outbound_push_bridge_resolve(
    body: JsonBody<OutboundPushBridgeResolveRequest>,
    depot: &mut Depot,
) -> JsonResult<OutboundPushBridgeResolveResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();

    let push_gateway_url = body.push_gateway_url.trim().to_owned();
    if push_gateway_url.is_empty() {
        return Err(AppError::invalid_param("push_gateway_url is required"));
    }

    let service_base_url =
        derive_push_gateway_service_base_url(&push_gateway_url).ok_or_else(|| {
            AppError::invalid_param("push_gateway_url must be an absolute push gateway URL")
        })?;
    let bridge_describe_url =
        join_edge_push_url(&service_base_url, "/_cokret/edge/push/bridge/describe");
    let cached = state
        .persistence
        .push_bridge_cache()
        .get(&bridge_describe_url)
        .await
        .ok()
        .flatten();
    let fetched_contract = cached
        .as_ref()
        .map(|record| outbound_push_resolved_contract_from_remote(&record.remote_contract))
        .unwrap_or_else(default_outbound_push_resolved_contract);

    json_ok(OutboundPushBridgeResolveResponse {
        push_gateway_url,
        service_base_url,
        bridge_describe_url,
        fetch_state: if let Some(record) = &cached {
            if body.refresh {
                format!(
                    "refresh_requested_cached_snapshot_present:{}",
                    record.fetch_state
                )
            } else {
                "resolved_with_cached_snapshot".to_owned()
            }
        } else if body.refresh {
            "refresh_requested_scaffold_only".to_owned()
        } else {
            "resolved_without_remote_fetch".to_owned()
        },
        cache_state: cached
            .as_ref()
            .map(|record| record.cache_state.clone())
            .unwrap_or_else(|| "not_persisted".to_owned()),
        contract_digest: cached
            .as_ref()
            .map(|record| record.contract_digest.clone())
            .unwrap_or_else(|| "scaffold-static".to_owned()),
        fetched_contract,
        todos: Vec::new(),
    })
}

#[endpoint(
    operation_id = "ck.extension.soland.push.outbound_bridge_fetch",
    tags("push"),
    summary = "Live-fetch the upstream push bridge contract + populate the durable cache"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ck.extension.soland.push.outbound_bridge_fetch")
)]
async fn outbound_push_bridge_fetch(
    body: JsonBody<OutboundPushBridgeFetchRequest>,
    depot: &mut Depot,
) -> JsonResult<OutboundPushBridgeFetchResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();

    let push_gateway_url = body.push_gateway_url.trim().to_owned();
    if push_gateway_url.is_empty() {
        return Err(AppError::invalid_param("push_gateway_url is required"));
    }
    let service_base_url =
        derive_push_gateway_service_base_url(&push_gateway_url).ok_or_else(|| {
            AppError::invalid_param("push_gateway_url must be an absolute push gateway URL")
        })?;
    let bridge_describe_url =
        join_edge_push_url(&service_base_url, "/_cokret/edge/push/bridge/describe");
    let bridge_describe_target = crate::security::validate_http_url_for_egress(
        &bridge_describe_url,
        "push bridge describe",
        state.config.development_mode,
    )
    .map_err(AppError::capability_denied)?;
    let existing_cache = state
        .persistence
        .push_bridge_cache()
        .get(&bridge_describe_url)
        .await
        .ok()
        .flatten();

    if !body.force_refresh {
        if let Some(record) = existing_cache.clone() {
            let mut response = outbound_push_bridge_fetch_response_from_cache(record.clone());
            if is_cache_entry_stale(state, &record) {
                response.trust_level = "stale".to_owned();
                response.fetch_state = "cache_hit_stale".to_owned();
            }
            return json_ok(response);
        }
    }

    let client = crate::security::build_default_egress_http_client(Duration::from_secs(10))
        .map_err(|error| AppError::internal(format!("build push bridge client: {error}")))?;
    let response = client
        .get(bridge_describe_target)
        .header("accept", "application/json")
        .send()
        .await;
    match response {
        Ok(response) if response.status().is_success() => {
            let etag = response
                .headers()
                .get(reqwest::header::ETAG)
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned)
                .unwrap_or_default();
            match response.json::<Value>().await {
                Ok(remote_contract) => {
                    let contract_digest = sha256_hex(
                        &serde_json::to_vec(&remote_contract).unwrap_or_else(|_| b"{}".to_vec()),
                    );
                    if let Some(existing) = existing_cache.clone() {
                        if existing.contract_digest != contract_digest && !body.force_refresh {
                            return json_ok(outbound_push_bridge_fetch_fallback(
                                Some(existing),
                                push_gateway_url,
                                service_base_url,
                                bridge_describe_url,
                                "contract_drift_detected_force_refresh_required".to_owned(),
                            ));
                        }
                    }
                    let fetched_at = now();
                    let fetched_contract =
                        outbound_push_resolved_contract_from_remote(&remote_contract);
                    let trust_level = resolve_trust_level(state, &fetched_contract);
                    let record = OutboundPushBridgeCacheRecord {
                        push_gateway_url: push_gateway_url.clone(),
                        service_base_url: service_base_url.clone(),
                        bridge_describe_url: bridge_describe_url.clone(),
                        fetch_state: "live_remote_fetch_ok".to_owned(),
                        cache_state: "memory_cached".to_owned(),
                        contract_digest: contract_digest.clone(),
                        fetched_at,
                        remote_contract: remote_contract.clone(),
                        trust_level,
                        freshness_at: fetched_at,
                        etag: etag.clone(),
                    };
                    if let Err(error) = state
                        .persistence
                        .push_bridge_cache()
                        .put(&bridge_describe_url, record.clone())
                        .await
                    {
                        tracing::error!(%error, "failed to persist push bridge cache entry");
                    }
                    json_ok(OutboundPushBridgeFetchResponse {
                        push_gateway_url,
                        service_base_url,
                        bridge_describe_url,
                        fetch_state: record.fetch_state.clone(),
                        cache_state: record.cache_state.clone(),
                        contract_digest,
                        fetched_at: Some(record.fetched_at),
                        fetched_contract: outbound_push_resolved_contract_from_remote(
                            &record.remote_contract,
                        ),
                        remote_contract: Some(remote_contract),
                        trust_level: record.trust_level.clone(),
                        freshness_at: Some(record.freshness_at),
                        etag,
                        todos: Vec::new(),
                    })
                }
                Err(error) => json_ok(outbound_push_bridge_fetch_fallback(
                    existing_cache,
                    push_gateway_url,
                    service_base_url,
                    bridge_describe_url,
                    format!("live_remote_fetch_bad_json:{error}"),
                )),
            }
        }
        Ok(response) => json_ok(outbound_push_bridge_fetch_fallback(
            existing_cache,
            push_gateway_url,
            service_base_url,
            bridge_describe_url,
            format!("live_remote_fetch_http_error:{}", response.status()),
        )),
        Err(error) => json_ok(outbound_push_bridge_fetch_fallback(
            existing_cache,
            push_gateway_url,
            service_base_url,
            bridge_describe_url,
            format!("live_remote_fetch_transport_error:{error}"),
        )),
    }
}

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "outbound_push_bridge_cache_status"))]
async fn outbound_push_bridge_cache_status(depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let entries = state
        .persistence
        .push_bridge_cache()
        .snapshot_all()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(outbound_push_bridge_cache_entry)
        .collect();
    res.render(Json(OutboundPushBridgeCacheStatusResponse { entries }));
}

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "outbound_push_bridge_cache_export"))]
async fn outbound_push_bridge_cache_export(depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let entries = state
        .persistence
        .push_bridge_cache()
        .snapshot_all()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(outbound_push_bridge_cache_snapshot)
        .collect();
    res.render(Json(OutboundPushBridgeCacheExportResponse {
        entries,
        snapshot_store_kind: "durable_push_bridge_cache".to_owned(),
        todos: Vec::new(),
    }));
}

#[endpoint(
    operation_id = "ck.extension.soland.push.outbound_bridge_cache_import",
    tags("push"),
    summary = "Import push bridge cache snapshots (replace_existing toggle)"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ck.extension.soland.push.outbound_bridge_cache_import")
)]
async fn outbound_push_bridge_cache_import(
    body: JsonBody<OutboundPushBridgeCacheImportRequest>,
    depot: &mut Depot,
) -> JsonResult<OutboundPushBridgeCacheImportResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    let replace_existing = body.replace_existing;
    let cache = state.persistence.push_bridge_cache();
    let mut imported_count = 0usize;
    let mut skipped_count = 0usize;
    for snapshot in body.entries {
        let exists = cache
            .get(&snapshot.bridge_describe_url)
            .await
            .ok()
            .flatten()
            .is_some();
        if !replace_existing && exists {
            skipped_count += 1;
            continue;
        }
        let url = snapshot.bridge_describe_url.clone();
        let mut record = outbound_push_bridge_cache_record(snapshot);
        // Honor the operator allowlist: an imported snapshot only lands at
        // `trust_level=trusted` if (a) we're in development_mode, or (b) the
        // upstream `service_did` is configured in
        // `push_bridge_trusted_service_dids`. Imports that claim
        // `trust_level=trusted` without satisfying either are demoted to
        // `pending` so the outbound delivery loop refuses to bind signed
        // delivery off them.
        let resolved = outbound_push_resolved_contract_from_remote(&record.remote_contract);
        let resolved_trust = resolve_trust_level(state, &resolved);
        if resolved_trust != "trusted" && record.trust_level == "trusted" {
            record.trust_level = "pending".to_owned();
        }
        if let Err(error) = cache.put(&url, record).await {
            tracing::error!(%error, "failed to persist imported push bridge cache entry");
            continue;
        }
        imported_count += 1;
    }
    let total_entries = cache.len().await.unwrap_or(0);
    json_ok(OutboundPushBridgeCacheImportResponse {
        imported_count,
        skipped_count,
        total_entries,
        snapshot_store_kind: "durable_push_bridge_cache".to_owned(),
        cache_state: if total_entries == 0 {
            "empty".to_owned()
        } else if replace_existing {
            "imported_replace_existing".to_owned()
        } else {
            "imported_merge_preserve_existing".to_owned()
        },
        todos: Vec::new(),
    })
}

#[endpoint(
    operation_id = "ck.extension.soland.push.outbound_bridge_cache_invalidate",
    tags("push"),
    summary = "Invalidate one or all push bridge cache entries"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ck.extension.soland.push.outbound_bridge_cache_invalidate")
)]
async fn outbound_push_bridge_cache_invalidate(
    body: JsonBody<OutboundPushBridgeCacheInvalidateRequest>,
    depot: &mut Depot,
) -> JsonResult<OutboundPushBridgeCacheInvalidateResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    let cache = state.persistence.push_bridge_cache();
    let removed_count = if let Some(push_gateway_url) = body
        .push_gateway_url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if let Some(service_base_url) = derive_push_gateway_service_base_url(push_gateway_url) {
            let bridge_describe_url =
                join_edge_push_url(&service_base_url, "/_cokret/edge/push/bridge/describe");
            usize::from(cache.delete(&bridge_describe_url).await.unwrap_or(false))
        } else {
            0
        }
    } else {
        cache.clear().await.unwrap_or(0)
    };
    let remaining_entries = cache.len().await.unwrap_or(0);
    json_ok(OutboundPushBridgeCacheInvalidateResponse {
        removed_count,
        remaining_entries,
        cache_state: if remaining_entries == 0 {
            "empty".to_owned()
        } else {
            "partially_retained".to_owned()
        },
    })
}

pub(super) fn derive_push_gateway_service_base_url(push_gateway_url: &str) -> Option<String> {
    let mut value = push_gateway_url.trim().trim_end_matches('/').to_owned();
    if value.is_empty() || !value.contains("://") {
        return None;
    }

    for suffix in [
        "/_cokret/edge/push/bridge/describe",
        "/cokret/push/v1/bridge/describe",
        "/_cokret/edge/push/notify",
        "/cokret/push/v1/notify",
        "/_cokret/edge/push",
        "/cokret/push/v1",
    ] {
        if let Some(prefix) = value.strip_suffix(suffix) {
            value = prefix.trim_end_matches('/').to_owned();
            break;
        }
    }

    if value.is_empty() { None } else { Some(value) }
}

pub(super) fn join_edge_push_url(base: &str, path: &str) -> String {
    let base = base.trim_end_matches('/');
    let path = path.trim_start_matches('/');
    let path = path.strip_prefix("_cokret/edge/").unwrap_or(path);

    if base.ends_with("/_cokret/edge") {
        format!("{base}/{path}")
    } else {
        format!("{base}/_cokret/edge/{path}")
    }
}

fn default_outbound_push_resolved_contract() -> OutboundPushResolvedContract {
    OutboundPushResolvedContract {
        contract: "ck.push.bridge.describe".to_owned(),
        expected_notify_path: "/_cokret/edge/push/notify".to_owned(),
        expected_operation_id: "ck.push.notify".to_owned(),
        expected_origin_service_did_header: "X-Cokret-Origin-Service-Did".to_owned(),
        expected_destination_service_did_header: "X-Cokret-Destination-Service-Did".to_owned(),
        expected_request_id_header: "X-Cokret-Request-Id".to_owned(),
        expected_idempotency_key_header: "Idempotency-Key".to_owned(),
        auth_modes: vec!["bearer".to_owned()],
        privacy_mode: "blind_wakeup".to_owned(),
        service_did: String::new(),
    }
}

fn outbound_push_resolved_contract_from_remote(
    remote_contract: &Value,
) -> OutboundPushResolvedContract {
    let fallback = default_outbound_push_resolved_contract();
    let auth_modes = remote_contract
        .pointer("/auth_modes")
        .or_else(|| remote_contract.pointer("/delivery/auth_modes"))
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or(fallback.auth_modes);
    let privacy_mode = remote_contract
        .pointer("/privacy/mode")
        .or_else(|| remote_contract.pointer("/privacy_mode"))
        .or_else(|| remote_contract.pointer("/delivery/privacy_mode"))
        .and_then(Value::as_str)
        .unwrap_or(&fallback.privacy_mode)
        .to_owned();
    let service_did = remote_contract
        .pointer("/service_did")
        .or_else(|| remote_contract.pointer("/origin/service_did"))
        .and_then(Value::as_str)
        .unwrap_or(&fallback.service_did)
        .to_owned();
    OutboundPushResolvedContract {
        contract: remote_contract
            .get("contract")
            .and_then(Value::as_str)
            .unwrap_or(&fallback.contract)
            .to_owned(),
        expected_notify_path: remote_contract
            .pointer("/delivery/notify_path")
            .or_else(|| remote_contract.get("notify_path"))
            .and_then(Value::as_str)
            .unwrap_or(&fallback.expected_notify_path)
            .to_owned(),
        expected_operation_id: remote_contract
            .pointer("/delivery/operation_id")
            .and_then(Value::as_str)
            .unwrap_or(&fallback.expected_operation_id)
            .to_owned(),
        expected_origin_service_did_header: remote_contract
            .pointer("/delivery/origin_service_did_header")
            .and_then(Value::as_str)
            .unwrap_or(&fallback.expected_origin_service_did_header)
            .to_owned(),
        expected_destination_service_did_header: remote_contract
            .pointer("/delivery/destination_service_did_header")
            .and_then(Value::as_str)
            .unwrap_or(&fallback.expected_destination_service_did_header)
            .to_owned(),
        expected_request_id_header: remote_contract
            .pointer("/delivery/request_id_header")
            .and_then(Value::as_str)
            .unwrap_or(&fallback.expected_request_id_header)
            .to_owned(),
        expected_idempotency_key_header: remote_contract
            .pointer("/delivery/idempotency_key_header")
            .and_then(Value::as_str)
            .unwrap_or(&fallback.expected_idempotency_key_header)
            .to_owned(),
        auth_modes,
        privacy_mode,
        service_did,
    }
}

/// Promote a contract to `trust_level=trusted` only when the upstream service
/// DID is in the operator's allowlist (or development_mode is on).
/// Otherwise stay at `pending` and let the outbound delivery loop decide
/// whether to fall back to unsigned delivery or refuse.
fn resolve_trust_level(state: &AppState, contract: &OutboundPushResolvedContract) -> String {
    if state.config.development_mode {
        return "trusted".to_owned();
    }
    if contract.service_did.is_empty() {
        return "pending".to_owned();
    }
    if state
        .config
        .push_bridge_trusted_service_dids
        .iter()
        .any(|allowed| allowed == &contract.service_did)
    {
        "trusted".to_owned()
    } else {
        "pending".to_owned()
    }
}

/// Returns true when the cached entry's `freshness_at` is older than the
/// configured `push_bridge_cache_ttl_seconds`. Used by the cache_hit path to
/// downgrade stale snapshots without a live re-fetch.
fn is_cache_entry_stale(state: &AppState, record: &OutboundPushBridgeCacheRecord) -> bool {
    let ttl = state.config.push_bridge_cache_ttl_seconds as i64;
    if ttl == 0 {
        return false;
    }
    let now_ts = now();
    let age = now_ts
        .signed_duration_since(record.freshness_at)
        .num_seconds();
    age > ttl
}

fn outbound_push_bridge_cache_entry(
    record: OutboundPushBridgeCacheRecord,
) -> OutboundPushBridgeCacheEntry {
    OutboundPushBridgeCacheEntry {
        push_gateway_url: record.push_gateway_url,
        service_base_url: record.service_base_url,
        bridge_describe_url: record.bridge_describe_url,
        fetch_state: record.fetch_state,
        cache_state: record.cache_state,
        contract_digest: record.contract_digest,
        fetched_at: record.fetched_at,
        fetched_contract: outbound_push_resolved_contract_from_remote(&record.remote_contract),
        trust_level: record.trust_level,
        freshness_at: record.freshness_at,
        etag: record.etag,
    }
}

fn outbound_push_bridge_cache_snapshot(
    record: OutboundPushBridgeCacheRecord,
) -> OutboundPushBridgeCacheSnapshot {
    OutboundPushBridgeCacheSnapshot {
        push_gateway_url: record.push_gateway_url,
        service_base_url: record.service_base_url,
        bridge_describe_url: record.bridge_describe_url,
        fetch_state: record.fetch_state,
        cache_state: record.cache_state,
        contract_digest: record.contract_digest,
        fetched_at: record.fetched_at,
        remote_contract: record.remote_contract,
        trust_level: record.trust_level,
        freshness_at: Some(record.freshness_at),
        etag: record.etag,
    }
}

fn outbound_push_bridge_cache_record(
    snapshot: OutboundPushBridgeCacheSnapshot,
) -> OutboundPushBridgeCacheRecord {
    let freshness_at = snapshot.freshness_at.unwrap_or(snapshot.fetched_at);
    OutboundPushBridgeCacheRecord {
        push_gateway_url: snapshot.push_gateway_url,
        service_base_url: snapshot.service_base_url,
        bridge_describe_url: snapshot.bridge_describe_url,
        fetch_state: snapshot.fetch_state,
        cache_state: snapshot.cache_state,
        contract_digest: snapshot.contract_digest,
        fetched_at: snapshot.fetched_at,
        remote_contract: snapshot.remote_contract,
        trust_level: snapshot.trust_level,
        freshness_at,
        etag: snapshot.etag,
    }
}

fn outbound_push_bridge_fetch_response_from_cache(
    record: OutboundPushBridgeCacheRecord,
) -> OutboundPushBridgeFetchResponse {
    let fetched_contract = outbound_push_resolved_contract_from_remote(&record.remote_contract);
    OutboundPushBridgeFetchResponse {
        push_gateway_url: record.push_gateway_url,
        service_base_url: record.service_base_url,
        bridge_describe_url: record.bridge_describe_url,
        fetch_state: "cache_hit".to_owned(),
        cache_state: record.cache_state,
        contract_digest: record.contract_digest,
        fetched_at: Some(record.fetched_at),
        fetched_contract,
        remote_contract: Some(record.remote_contract),
        trust_level: record.trust_level,
        freshness_at: Some(record.freshness_at),
        etag: record.etag,
        todos: Vec::new(),
    }
}

fn outbound_push_bridge_fetch_fallback(
    existing_cache: Option<OutboundPushBridgeCacheRecord>,
    push_gateway_url: String,
    service_base_url: String,
    bridge_describe_url: String,
    fetch_state: String,
) -> OutboundPushBridgeFetchResponse {
    if let Some(record) = existing_cache {
        let mut response = outbound_push_bridge_fetch_response_from_cache(record);
        response.fetch_state = format!("{fetch_state}:stale_cache_returned");
        return response;
    }

    OutboundPushBridgeFetchResponse {
        push_gateway_url,
        service_base_url,
        bridge_describe_url,
        fetch_state,
        cache_state: "not_cached".to_owned(),
        contract_digest: "scaffold-static".to_owned(),
        fetched_at: None,
        fetched_contract: default_outbound_push_resolved_contract(),
        remote_contract: None,
        trust_level: "pending".to_owned(),
        freshness_at: None,
        etag: String::new(),
        todos: Vec::new(),
    }
}
