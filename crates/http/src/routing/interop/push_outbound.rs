//! Internal canonical push-gateway discovery and durable snapshot refresh.
//!
//! There is deliberately no product-private HTTP management surface here.
//! `push_notify` refreshes a missing or stale snapshot from the gateway's
//! canonical `/_arkret/describe` endpoint before applying the fail-closed
//! trust/freshness gate.

use std::time::Duration;

use arkret_models_discovery::ServiceDescribe;
use arkret_wire::{BindingKind, ServiceKind, ServiceOperationId};
use soland_services::delivery::OutboundPushBridgeCacheState;

use super::{now, sha256_hex};
use crate::state::AppState;

pub(super) fn derive_push_gateway_service_base_url(push_gateway_url: &str) -> Option<String> {
    let mut value = push_gateway_url.trim().trim_end_matches('/').to_owned();
    if value.is_empty() || !value.contains("://") {
        return None;
    }

    for suffix in [
        "/_arkret/describe",
        "/_arkret/edge/push/notify",
        "/_arkret/edge/push",
    ] {
        if let Some(prefix) = value.strip_suffix(suffix) {
            value = prefix.trim_end_matches('/').to_owned();
            break;
        }
    }

    if value.is_empty() { None } else { Some(value) }
}

pub(super) fn join_push_gateway_url(base: &str, path: &str) -> String {
    format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

pub(super) async fn refresh_push_gateway_description(
    state: &AppState,
    push_gateway_url: &str,
) -> Result<(), String> {
    let service_base_url = derive_push_gateway_service_base_url(push_gateway_url)
        .ok_or_else(|| "push_gateway must be an absolute canonical gateway URL".to_owned())?;
    let describe_url = join_push_gateway_url(&service_base_url, "/_arkret/describe");
    let (target, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        &describe_url,
        "push gateway ServiceDescribe",
        state.config().development_mode,
        Duration::from_secs(10),
    )
    .map_err(|error| error.to_string())?;

    let response = client
        .get(target)
        .header("accept", "application/json")
        .send()
        .await
        .map_err(|error| format!("push gateway discovery transport error: {error}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "push gateway discovery returned HTTP {}",
            response.status()
        ));
    }
    let etag = response
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
        .unwrap_or_default();
    let description = response
        .json::<ServiceDescribe>()
        .await
        .map_err(|error| format!("invalid canonical ServiceDescribe JSON: {error}"))?;
    validate_push_gateway_description(&description, &service_base_url)?;

    let remote_contract = serde_json::to_value(&description)
        .map_err(|error| format!("serialize canonical ServiceDescribe: {error}"))?;
    let contract_digest = sha256_hex(
        &serde_json::to_vec(&remote_contract)
            .map_err(|error| format!("serialize ServiceDescribe digest input: {error}"))?,
    );
    let fetched_at = now();
    let record = OutboundPushBridgeCacheState {
        push_gateway_url: push_gateway_url.trim().to_owned(),
        service_base_url,
        bridge_describe_url: describe_url.clone(),
        fetch_state: "canonical_service_describe_fetch_ok".to_owned(),
        cache_state: "durable_cached".to_owned(),
        contract_digest,
        fetched_at,
        remote_contract,
        trust_level: resolve_trust_level(state, &description),
        freshness_at: fetched_at,
        etag,
    };
    state
        .deliveries()
        .store_push_bridge_cache_entry(&describe_url, record)
        .await
        .map_err(|error| format!("persist push gateway discovery snapshot: {error}"))
}

fn validate_push_gateway_description(
    description: &ServiceDescribe,
    service_base_url: &str,
) -> Result<(), String> {
    description.validate().map_err(|error| error.to_string())?;
    if description.service_kind != ServiceKind::PushGateway {
        return Err("service_kind must be push_gateway".to_owned());
    }
    let Some(binding) = description.select_transport_binding(
        ServiceOperationId::EdgePushCommandNotifyV1,
        &[BindingKind::HttpJson],
    ) else {
        return Err("canonical HTTP push notify operation is not advertised".to_owned());
    };
    let advertised_base = derive_push_gateway_service_base_url(binding.base_url())
        .ok_or_else(|| "push gateway HTTP binding is not an absolute URL".to_owned())?;
    if advertised_base != service_base_url {
        return Err("push gateway HTTP binding origin does not match requested gateway".to_owned());
    }
    Ok(())
}

fn resolve_trust_level(state: &AppState, description: &ServiceDescribe) -> String {
    if state.config().development_mode
        || state
            .settings()
            .push_bridge_trusted_ids
            .iter()
            .any(|allowed| allowed == description.service_id.as_str())
    {
        "trusted".to_owned()
    } else {
        "pending".to_owned()
    }
}
