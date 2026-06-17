use cokret_sdk::Operation;
use salvo::http::StatusCode;
use serde_json::Value;

use super::outbound::parse_peer_target;
use super::validate_did;
use crate::error::AppError;
use crate::routing::policy_gate::{self, PolicyGateSurface};
use crate::state::AppState;

pub(super) const MAX_INBOUND_FEDERATION_OPERATIONS: usize = 500;

/// SPEC-CR-008 (federation.md §4.0) — the cross-deployment federation Event
/// receive rail is converged onto a single track: `POST /_cokret/peer/events`
/// (`ck.peer.events.command.submit`). The `/_soland/peer/*` inbound
/// *write* surface (transactions, operations push/backfill, seals push) is a
/// deployment-local test/ops rail only and MUST NOT serve as a cross-vendor
/// interop entry point: it MUST NOT accept Move/Anchor/Operation pushes from a
/// remote federation peer.
///
/// This guard fail-closes those write tracks outside deployment-local mode so
/// the only inbound interop posture is the protocol track. Read-only debug
/// tracks (pull/frontier/realm-members/actor-events/seals-pull) are not gated:
/// they expose no interop write surface. When the rail is disabled the error
/// points callers at the canonical receive track.
pub(crate) fn ensure_private_inbound_write_rail_local(state: &AppState) -> Result<(), AppError> {
    if state.config.development_mode {
        return Ok(());
    }
    Err(AppError::unsupported_feature(
        "the /_soland/peer/* inbound write rail is a deployment-local test/ops affordance and is \
         not a cross-deployment federation interop entry point; submit sealed Event Envelopes to \
         the protocol track POST /_cokret/peer/events (ck.peer.events.command.submit) instead",
    )
    .with_wire_code("federation_interop_track_only"))
}

pub(super) async fn enforce_inbound_operation_batch_policy(
    state: &AppState,
    origin_service_did: &str,
    operations: &[Operation],
) -> Result<(), AppError> {
    if operations.len() > MAX_INBOUND_FEDERATION_OPERATIONS {
        return Err(AppError::new(
            crate::error::ErrorCode::PayloadTooLarge,
            format!(
                "federation operation batch exceeds limit: {} > {}",
                operations.len(),
                MAX_INBOUND_FEDERATION_OPERATIONS
            ),
        )
        .with_status(StatusCode::PAYLOAD_TOO_LARGE)
        .with_wire_code("payload_too_large"));
    }
    for operation in operations {
        enforce_realm_federation_policy(
            state,
            operation.realm_id.as_str(),
            origin_service_did,
            None,
            FederationDirection::Inbound,
        )?;
        enforce_realm_moderation_federation_policy(
            state,
            operation.realm_id.as_str(),
            origin_service_did,
            None,
            FederationDirection::Inbound,
        )?;
        policy_gate::enforce_operation_policy_server(
            state,
            operation_actor_id(operation).unwrap_or(origin_service_did),
            operation,
            PolicyGateSurface::FederationInbound {
                origin_service_did: origin_service_did.to_owned(),
            },
        )
        .await
        .map_err(app_error_from_policy_gate)?;
    }
    Ok(())
}

fn app_error_from_policy_gate(rejection: policy_gate::PolicyGateRejection) -> AppError {
    AppError::new(crate::error::ErrorCode::CapabilityDenied, rejection.message)
        .with_status(rejection.status)
        .with_wire_code(rejection.code)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FederationDirection {
    Inbound,
    Outbound,
}

fn enforce_realm_federation_policy(
    state: &AppState,
    realm_id: &str,
    peer_did: &str,
    peer_url: Option<&str>,
    direction: FederationDirection,
) -> Result<(), AppError> {
    let policy = state
        .projection
        .lock()
        .map_err(|error| AppError::internal(format!("projection lock: {error}")))?
        .realm_federation_policy(realm_id)
        .unwrap_or_else(|| "open".to_owned());
    match policy.as_str() {
        "open" | "mesh" | "hub" => Ok(()),
        "closed" | "disabled" => Err(AppError::capability_denied(
            "realm federation_policy forbids federation",
        )
        .with_wire_code("realm_federation_policy_closed")),
        "quarantine" => Err(AppError::capability_denied(
            "realm federation_policy is quarantine; live federation is blocked",
        )
        .with_wire_code("realm_federation_policy_quarantine")),
        "restricted" => {
            if direction == FederationDirection::Outbound
                || configured_peer_matches(state, peer_did, peer_url)
            {
                Ok(())
            } else {
                Err(AppError::capability_denied(
                    "realm federation_policy=restricted requires a configured peer",
                )
                .with_wire_code("realm_federation_policy_restricted"))
            }
        }
        _ => Err(
            AppError::capability_denied("realm federation_policy has an unsupported value")
                .with_wire_code("realm_federation_policy_invalid"),
        ),
    }
}

fn enforce_realm_moderation_federation_policy(
    state: &AppState,
    realm_id: &str,
    peer_did: &str,
    peer_url: Option<&str>,
    direction: FederationDirection,
) -> Result<(), AppError> {
    let record = state
        .realm_moderation_policies
        .lock()
        .expect("realm moderation policies lock")
        .get(realm_id)
        .cloned();
    let Some(record) = record else {
        return Ok(());
    };
    if let Some(reason) =
        moderation_policy_denies_federation(&record.payload, peer_did, peer_url, direction)
    {
        return Err(
            AppError::capability_denied(reason).with_wire_code("realm_moderation_policy_denied")
        );
    }
    Ok(())
}

fn moderation_policy_denies_federation(
    policy: &Value,
    peer_did: &str,
    peer_url: Option<&str>,
    direction: FederationDirection,
) -> Option<String> {
    let allowlist_enforced = ["allowlist_enforced", "federation_allowlist_enforced"]
        .iter()
        .any(|key| policy.get(key).and_then(Value::as_bool) == Some(true));
    let mut explicitly_allowed = false;

    for key in ["rules", "targets", "server_targets", "federation_targets"] {
        let Some(entries) = policy.get(key).and_then(Value::as_array) else {
            continue;
        };
        for entry in entries {
            if !moderation_target_matches_peer(entry, peer_did, peer_url) {
                continue;
            }
            let action = moderation_action(entry);
            if moderation_action_allows_federation(action, direction) {
                explicitly_allowed = true;
            }
            if moderation_action_denies_federation(action, direction) {
                return Some(format!(
                    "realm moderation policy blocks federation peer {peer_did}"
                ));
            }
        }
    }

    if allowlist_enforced && !explicitly_allowed {
        return Some(format!(
            "realm moderation policy allowlist does not include federation peer {peer_did}"
        ));
    }
    None
}

fn moderation_action(entry: &Value) -> &str {
    entry
        .get("action")
        .or_else(|| entry.get("effect"))
        .or_else(|| entry.get("polarity"))
        .or_else(|| entry.get("mode"))
        .and_then(Value::as_str)
        .unwrap_or_default()
}

fn moderation_action_denies_federation(action: &str, direction: FederationDirection) -> bool {
    matches!(
        action,
        "deny" | "block" | "defederate" | "deny_federation" | "block_federation"
    ) || matches!(
        (direction, action),
        (
            FederationDirection::Inbound,
            "deny_inbound" | "block_inbound"
        ) | (
            FederationDirection::Outbound,
            "deny_outbound" | "block_outbound"
        )
    )
}

fn moderation_action_allows_federation(action: &str, direction: FederationDirection) -> bool {
    matches!(
        action,
        "allow" | "allow_federation" | "allow_peer" | "allow_server"
    ) || matches!(
        (direction, action),
        (FederationDirection::Inbound, "allow_inbound")
            | (FederationDirection::Outbound, "allow_outbound")
    )
}

fn moderation_target_matches_peer(entry: &Value, peer_did: &str, peer_url: Option<&str>) -> bool {
    let target = entry.get("target").unwrap_or(entry);
    let kind = target
        .get("kind")
        .or_else(|| entry.get("kind"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let server_kind = matches!(
        kind,
        "server" | "service" | "service_did" | "peer" | "federation_peer" | "federation_server"
    );
    let did_matches = ["did", "service_did", "server_did", "peer_did", "target_did"]
        .iter()
        .filter_map(|key| target.get(*key).or_else(|| entry.get(*key)))
        .any(|value| value.as_str() == Some(peer_did));
    let string_target_matches = target.as_str() == Some(peer_did);
    let url_matches = peer_url.is_some_and(|peer_url| {
        ["url", "base_url", "peer_url", "server_url"]
            .iter()
            .filter_map(|key| target.get(*key).or_else(|| entry.get(*key)))
            .any(|value| value.as_str() == Some(peer_url))
    });
    server_kind && (did_matches || string_target_matches || url_matches)
}

fn configured_peer_matches(state: &AppState, peer_did: &str, peer_url: Option<&str>) -> bool {
    state
        .config
        .federation_peers
        .iter()
        .filter_map(|entry| parse_peer_target(entry))
        .any(|peer| {
            peer.did == peer_did
                || peer_url
                    .is_some_and(|url| peer.url.trim_end_matches('/') == url.trim_end_matches('/'))
        })
}

fn operation_actor_id(operation: &Operation) -> Option<&str> {
    [
        "sender",
        "actor",
        "actor_id",
        "member",
        "subject",
        "created_by",
        "updated_by",
    ]
    .iter()
    .find_map(|field| operation.payload.get(*field).and_then(Value::as_str))
    .filter(|did| validate_did(did).is_ok())
}
