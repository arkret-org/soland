//! Outbound push gateway bridge — describe / resolve / fetch / cache.
//!
//! Surfaces:
//! - `GET  /api/v1/push/outbound/bridge/describe`        — manifest scaffold
//! - `POST /api/v1/push/outbound/bridge/resolve`         — resolve gateway URL → contract
//! - `POST /api/v1/push/outbound/bridge/fetch`           — pull remote contract + cache
//! - `GET  /api/v1/push/outbound/bridge/cache/status`    — current cache age
//! - `GET  /api/v1/push/outbound/bridge/cache/export`    — dump cache snapshots
//! - `POST /api/v1/push/outbound/bridge/cache/import`    — restore snapshots
//! - `POST /api/v1/push/outbound/bridge/cache/invalidate`— invalidate one entry
//!
//! Every route is a scaffold today. The full set of TODOs is in `_todos.md`
//! Stream-F-8: durable snapshot store, etag/freshness, signed-service-DID
//! trust, contract-drift fail-closed, persisted gateway snapshots used in
//! notification fan-out. The helpers (`outbound_push_resolved_contract_from_remote`,
//! `outbound_push_bridge_cache_*`, `derive_push_gateway_service_base_url`,
//! `join_api_v1_url`, `default_outbound_push_resolved_contract`,
//! `render_outbound_push_bridge_fetch_fallback`) all stay private to this
//! module — none cross domain.

use salvo::{http::StatusCode, prelude::*};
use serde_json::{Value, json};

use crate::{
    state::{AppState, OutboundPushBridgeCacheRecord},
    wire::{
        OutboundPushBridgeCacheEntry, OutboundPushBridgeCacheExportResponse,
        OutboundPushBridgeCacheImportRequest, OutboundPushBridgeCacheImportResponse,
        OutboundPushBridgeCacheInvalidateRequest, OutboundPushBridgeCacheInvalidateResponse,
        OutboundPushBridgeCacheSnapshot, OutboundPushBridgeCacheStatusResponse,
        OutboundPushBridgeDescribeResponse, OutboundPushBridgeExamples,
        OutboundPushBridgeFetchRequest, OutboundPushBridgeFetchResponse,
        OutboundPushBridgeResolveRequest, OutboundPushBridgeResolveResponse,
        OutboundPushDeliveryDescriptor, OutboundPushGatewayContractDescriptor,
        OutboundPushResolvedContract,
    },
};

use super::{now, render_error, sha256_hex};

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
async fn outbound_push_bridge_describe(depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    res.render(Json(OutboundPushBridgeDescribeResponse {
        contract: "contrix.rest.outbound_push_bridge.v1".to_owned(),
        version: "2026-05-04-scaffold".to_owned(),
        api_base_path: "/api/v1/push".to_owned(),
        gateway_contract: OutboundPushGatewayContractDescriptor {
            resolve_path: "/api/v1/push/outbound/bridge/resolve".to_owned(),
            fetch_path: "/api/v1/push/outbound/bridge/fetch".to_owned(),
            cache_status_path: "/api/v1/push/outbound/bridge/cache/status".to_owned(),
            cache_invalidate_path: "/api/v1/push/outbound/bridge/cache/invalidate".to_owned(),
            cache_export_path: "/api/v1/push/outbound/bridge/cache/export".to_owned(),
            cache_import_path: "/api/v1/push/outbound/bridge/cache/import".to_owned(),
            bridge_describe_path: "/api/v1/push/bridge/describe".to_owned(),
            notify_path: "/api/v1/push/notify".to_owned(),
            accepted_contracts: vec![
                "cx.push.bridge.describe".to_owned(),
                "cx.profile.push_gateway.v1".to_owned(),
            ],
            fetch_mode: "live_http_fetch_with_scaffold_fallback".to_owned(),
            cache_mode: "in_memory_snapshot_cache".to_owned(),
            snapshot_store_mode: "export_import_scaffold_over_process_memory".to_owned(),
        },
        delivery: OutboundPushDeliveryDescriptor {
            operation_id: "cx.push.notify".to_owned(),
            origin_service_did_header: "X-Contrix-Origin-Service-Did".to_owned(),
            destination_service_did_header: "X-Contrix-Destination-Service-Did".to_owned(),
            request_id_header: "X-Contrix-Request-Id".to_owned(),
            idempotency_key_header: "Idempotency-Key".to_owned(),
            payload_mode: format!(
                "blind_wakeup_from_principal_service_did={}",
                state.config.service_did
            ),
        },
        examples: OutboundPushBridgeExamples {
            resolve_request: json!({
                "push_gateway_url": "https://floria.example/api/v1/push/notify",
                "refresh": false
            }),
            fetch_request: json!({
                "push_gateway_url": "https://floria.example/api/v1/push/notify",
                "force_refresh": true
            }),
            notify_headers: json!({
                "X-Contrix-Origin-Service-Did": state.config.service_did,
                "X-Contrix-Destination-Service-Did": "did:web:floria.example",
                "X-Contrix-Request-Id": "req_01js0000000000000000000000",
                "Idempotency-Key": "notify-01js0000000000000000000000"
            }),
            cache_import_request: json!({
                "replace_existing": true,
                "entries": [{
                    "push_gateway_url": "https://floria.example/api/v1/push/notify",
                    "service_base_url": "https://floria.example",
                    "bridge_describe_url": "https://floria.example/api/v1/push/bridge/describe",
                    "fetch_state": "seed_import",
                    "cache_state": "imported_snapshot_scaffold",
                    "contract_digest": "sha256:TODO",
                    "fetched_at": now(),
                    "remote_contract": {
                        "contract": "cx.push.bridge.describe",
                        "delivery": {
                            "notify_path": "/api/v1/push/notify",
                            "operation_id": "cx.push.notify"
                        }
                    }
                }]
            }),
            cache_export_response: json!({
                "entries": [{
                    "push_gateway_url": "https://floria.example/api/v1/push/notify",
                    "service_base_url": "https://floria.example",
                    "bridge_describe_url": "https://floria.example/api/v1/push/bridge/describe",
                    "fetch_state": "cache_hit",
                    "cache_state": "imported_snapshot_scaffold",
                    "contract_digest": "sha256:TODO",
                    "remote_contract": {
                        "contract": "cx.push.bridge.describe"
                    }
                }],
                "snapshot_store_kind": "process_memory_export_import_scaffold"
            }),
        },
        todos: vec![
            "TODO(push-outbound): fetch remote gateway bridge metadata from configured push_gateway origins before first delivery".to_owned(),
            "TODO(push-outbound): cache gateway contract snapshots and refuse contract drift without explicit refresh".to_owned(),
            "TODO(push-outbound): replace export/import scaffold with durable snapshot persistence and explicit trust policy".to_owned(),
            "TODO(push-outbound): bind outbound notify signing/auth policy to the discovered gateway contract instead of static assumptions".to_owned(),
        ],
    }));
}

#[endpoint]
async fn outbound_push_bridge_resolve(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = match req.parse_json::<OutboundPushBridgeResolveRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid outbound push bridge resolve request",
            );
            return;
        }
    };

    let push_gateway_url = body.push_gateway_url.trim().to_owned();
    if push_gateway_url.is_empty() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "push_gateway_url is required",
        );
        return;
    }

    let Some(service_base_url) = derive_push_gateway_service_base_url(&push_gateway_url) else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "push_gateway_url must be an absolute push gateway URL",
        );
        return;
    };
    let bridge_describe_url = join_api_v1_url(&service_base_url, "/api/v1/push/bridge/describe");
    let cached = state
        .persistence
        .push_bridge_cache()
        .get(&bridge_describe_url)
        .ok()
        .flatten();
    let fetched_contract = cached
        .as_ref()
        .map(|record| outbound_push_resolved_contract_from_remote(&record.remote_contract))
        .unwrap_or_else(default_outbound_push_resolved_contract);

    res.render(Json(OutboundPushBridgeResolveResponse {
        push_gateway_url,
        service_base_url,
        bridge_describe_url,
        fetch_state: if let Some(record) = &cached {
            if body.refresh {
                format!("refresh_requested_cached_snapshot_present:{}", record.fetch_state)
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
        todos: vec![
            "TODO(push-outbound): perform live fetch of the remote bridge_describe_url before first delivery".to_owned(),
            "TODO(push-outbound): persist contract snapshots and freshness metadata instead of returning static cache_state".to_owned(),
            "TODO(push-outbound): bind outbound delivery policy to fetched auth_modes/privacy descriptors instead of fixed expectations".to_owned(),
        ],
    }));
}

#[endpoint]
async fn outbound_push_bridge_fetch(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = match req.parse_json::<OutboundPushBridgeFetchRequest>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid outbound push bridge fetch request",
            );
            return;
        }
    };

    let push_gateway_url = body.push_gateway_url.trim().to_owned();
    if push_gateway_url.is_empty() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "push_gateway_url is required",
        );
        return;
    }
    let Some(service_base_url) = derive_push_gateway_service_base_url(&push_gateway_url) else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "push_gateway_url must be an absolute push gateway URL",
        );
        return;
    };
    let bridge_describe_url = join_api_v1_url(&service_base_url, "/api/v1/push/bridge/describe");
    let existing_cache = state
        .persistence
        .push_bridge_cache()
        .get(&bridge_describe_url)
        .ok()
        .flatten();

    if !body.force_refresh {
        if let Some(record) = existing_cache.clone() {
            res.render(Json(outbound_push_bridge_fetch_response_from_cache(record)));
            return;
        }
    }

    let response = reqwest::Client::new()
        .get(&bridge_describe_url)
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
                            render_outbound_push_bridge_fetch_fallback(
                                Some(existing),
                                push_gateway_url,
                                service_base_url,
                                bridge_describe_url,
                                "contract_drift_detected_force_refresh_required".to_owned(),
                                res,
                            );
                            return;
                        }
                    }
                    let fetched_at = now();
                    let record = OutboundPushBridgeCacheRecord {
                        push_gateway_url: push_gateway_url.clone(),
                        service_base_url: service_base_url.clone(),
                        bridge_describe_url: bridge_describe_url.clone(),
                        fetch_state: "live_remote_fetch_ok".to_owned(),
                        cache_state: "memory_cached".to_owned(),
                        contract_digest: contract_digest.clone(),
                        fetched_at,
                        remote_contract: remote_contract.clone(),
                        trust_level: "trusted".to_owned(),
                        freshness_at: fetched_at,
                        etag: etag.clone(),
                    };
                    if let Err(error) = state
                        .persistence
                        .push_bridge_cache()
                        .put(&bridge_describe_url, record.clone())
                    {
                        tracing::error!(%error, "failed to persist push bridge cache entry");
                    }
                    res.render(Json(OutboundPushBridgeFetchResponse {
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
                    todos: vec![
                        "TODO(push-outbound): validate fetched auth/privacy modes before enabling signed delivery".to_owned(),
                        "TODO(push-outbound): persist cache entries outside process memory and attach freshness/etag metadata".to_owned(),
                    ],
                }));
                }
                Err(error) => {
                    render_outbound_push_bridge_fetch_fallback(
                        existing_cache,
                        push_gateway_url,
                        service_base_url,
                        bridge_describe_url,
                        format!("live_remote_fetch_bad_json:{error}"),
                        res,
                    );
                }
            }
        }
        Ok(response) => {
            render_outbound_push_bridge_fetch_fallback(
                existing_cache,
                push_gateway_url,
                service_base_url,
                bridge_describe_url,
                format!("live_remote_fetch_http_error:{}", response.status()),
                res,
            );
        }
        Err(error) => {
            render_outbound_push_bridge_fetch_fallback(
                existing_cache,
                push_gateway_url,
                service_base_url,
                bridge_describe_url,
                format!("live_remote_fetch_transport_error:{error}"),
                res,
            );
        }
    }
}

#[endpoint]
async fn outbound_push_bridge_cache_status(depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let entries = state
        .persistence
        .push_bridge_cache()
        .snapshot_all()
        .unwrap_or_default()
        .into_iter()
        .map(outbound_push_bridge_cache_entry)
        .collect();
    res.render(Json(OutboundPushBridgeCacheStatusResponse { entries }));
}

#[endpoint]
async fn outbound_push_bridge_cache_export(depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let entries = state
        .persistence
        .push_bridge_cache()
        .snapshot_all()
        .unwrap_or_default()
        .into_iter()
        .map(outbound_push_bridge_cache_snapshot)
        .collect();
    res.render(Json(OutboundPushBridgeCacheExportResponse {
        entries,
        snapshot_store_kind: "process_memory_export_import_scaffold".to_owned(),
        todos: vec![
            "TODO(push-outbound): persist exported snapshots in a durable store instead of requiring clients to carry them around.".to_owned(),
            "TODO(push-outbound): attach trust/freshness metadata before treating imported snapshots as production-grade gateway state.".to_owned(),
        ],
    }));
}

#[endpoint]
async fn outbound_push_bridge_cache_import(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = match req
        .parse_json::<OutboundPushBridgeCacheImportRequest>()
        .await
    {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid outbound push bridge cache import request",
            );
            return;
        }
    };
    let replace_existing = body.replace_existing;
    let cache = state.persistence.push_bridge_cache();
    let mut imported_count = 0usize;
    let mut skipped_count = 0usize;
    for snapshot in body.entries {
        let exists = cache
            .get(&snapshot.bridge_describe_url)
            .ok()
            .flatten()
            .is_some();
        if !replace_existing && exists {
            skipped_count += 1;
            continue;
        }
        let url = snapshot.bridge_describe_url.clone();
        if let Err(error) = cache.put(&url, outbound_push_bridge_cache_record(snapshot)) {
            tracing::error!(%error, "failed to persist imported push bridge cache entry");
            continue;
        }
        imported_count += 1;
    }
    let total_entries = cache.len().unwrap_or(0);
    res.render(Json(OutboundPushBridgeCacheImportResponse {
        imported_count,
        skipped_count,
        total_entries,
        snapshot_store_kind: "process_memory_export_import_scaffold".to_owned(),
        cache_state: if total_entries == 0 {
            "empty".to_owned()
        } else if replace_existing {
            "imported_replace_existing_scaffold".to_owned()
        } else {
            "imported_merge_preserve_existing_scaffold".to_owned()
        },
        todos: vec![
            "TODO(push-outbound): validate imported snapshots against service DID trust, contract version, and freshness before production use.".to_owned(),
            "TODO(push-outbound): replace process-memory import with a durable snapshot store and explicit drift-resolution policy.".to_owned(),
        ],
    }));
}

#[endpoint]
async fn outbound_push_bridge_cache_invalidate(
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = req
        .parse_json::<OutboundPushBridgeCacheInvalidateRequest>()
        .await
        .unwrap_or(OutboundPushBridgeCacheInvalidateRequest {
            push_gateway_url: None,
        });
    let cache = state.persistence.push_bridge_cache();
    let removed_count = if let Some(push_gateway_url) = body
        .push_gateway_url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if let Some(service_base_url) = derive_push_gateway_service_base_url(push_gateway_url) {
            let bridge_describe_url =
                join_api_v1_url(&service_base_url, "/api/v1/push/bridge/describe");
            usize::from(cache.delete(&bridge_describe_url).unwrap_or(false))
        } else {
            0
        }
    } else {
        cache.clear().unwrap_or(0)
    };
    let remaining_entries = cache.len().unwrap_or(0);
    res.render(Json(OutboundPushBridgeCacheInvalidateResponse {
        removed_count,
        remaining_entries,
        cache_state: if remaining_entries == 0 {
            "empty".to_owned()
        } else {
            "partially_retained".to_owned()
        },
    }));
}

pub(super) fn derive_push_gateway_service_base_url(push_gateway_url: &str) -> Option<String> {
    let mut value = push_gateway_url.trim().trim_end_matches('/').to_owned();
    if value.is_empty() || !value.contains("://") {
        return None;
    }

    for suffix in [
        "/api/v1/push/bridge/describe",
        "/contrix/push/v1/bridge/describe",
        "/api/v1/push/notify",
        "/contrix/push/v1/notify",
        "/api/v1/push",
        "/contrix/push/v1",
    ] {
        if let Some(prefix) = value.strip_suffix(suffix) {
            value = prefix.trim_end_matches('/').to_owned();
            break;
        }
    }

    if value.is_empty() { None } else { Some(value) }
}

pub(super) fn join_api_v1_url(base: &str, path: &str) -> String {
    let base = base.trim_end_matches('/');
    let path = path.trim_start_matches('/');
    let path = path.strip_prefix("api/v1/").unwrap_or(path);

    if base.ends_with("/api/v1") {
        format!("{base}/{path}")
    } else {
        format!("{base}/api/v1/{path}")
    }
}

fn default_outbound_push_resolved_contract() -> OutboundPushResolvedContract {
    OutboundPushResolvedContract {
        contract: "cx.push.bridge.describe".to_owned(),
        expected_notify_path: "/api/v1/push/notify".to_owned(),
        expected_operation_id: "cx.push.notify".to_owned(),
        expected_origin_service_did_header: "X-Contrix-Origin-Service-Did".to_owned(),
        expected_destination_service_did_header: "X-Contrix-Destination-Service-Did".to_owned(),
        expected_request_id_header: "X-Contrix-Request-Id".to_owned(),
        expected_idempotency_key_header: "Idempotency-Key".to_owned(),
    }
}

fn outbound_push_resolved_contract_from_remote(
    remote_contract: &Value,
) -> OutboundPushResolvedContract {
    let fallback = default_outbound_push_resolved_contract();
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
    }
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
        todos: vec![
            "TODO(push-outbound): persist cache entries outside process memory and attach freshness/etag metadata".to_owned(),
            "TODO(push-outbound): add explicit cache invalidation policy instead of only force_refresh".to_owned(),
        ],
    }
}

fn render_outbound_push_bridge_fetch_fallback(
    existing_cache: Option<OutboundPushBridgeCacheRecord>,
    push_gateway_url: String,
    service_base_url: String,
    bridge_describe_url: String,
    fetch_state: String,
    res: &mut Response,
) {
    if let Some(record) = existing_cache {
        let mut response = outbound_push_bridge_fetch_response_from_cache(record);
        response.fetch_state = format!("{fetch_state}:stale_cache_returned");
        res.render(Json(response));
        return;
    }

    res.render(Json(OutboundPushBridgeFetchResponse {
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
        todos: vec![
            "TODO(push-outbound): retry remote bridge fetch and persist the first successful contract snapshot".to_owned(),
            "TODO(push-outbound): fail closed on contract drift once a persisted snapshot exists".to_owned(),
        ],
    }));
}
