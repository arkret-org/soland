use arkret_core::Operation;
use salvo::http::StatusCode;
use serde_json::Value;
use soland_http::error::AppError;

use super::outbound::parse_peer_target;
use crate::routing::policy_gate::{self, PolicyGateSurface};
use crate::state::AppState;

pub(super) const MAX_INBOUND_FEDERATION_OPERATIONS: usize = 500;

/// SPEC-CR-008 (federation.md §4.0) — the cross-deployment federation Event
/// receive rail is converged onto a single track: `POST /_arkret/peer/events`
/// (`ak.peer.events.command.submit`). The `/_soland/peer/*` inbound
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
    if state.config().development_mode {
        return Ok(());
    }
    Err(AppError::unsupported_feature(
        "the /_soland/peer/* inbound write rail is a deployment-local test/ops affordance and is \
         not a cross-deployment federation interop entry point; submit sealed Event Envelopes to \
         the protocol track POST /_arkret/peer/events (ak.peer.events.command.submit) instead",
    )
    .with_wire_code("federation_interop_track_only"))
}

/// SOL-SEC-01 (federation.md §1) — the `/_soland/peer/federation/*` inbound
/// *read* rail (seals-pull, realm-members, actor-events, pull-operations,
/// operation-frontier) is unauthenticated: it carries no RFC 9421 service
/// signature / PoP like the protocol `/_arkret/peer/*` track. Leaving it open
/// would expose Realm membership, the Seal DAG, and per-actor projection events
/// to any unauthenticated caller that can reach the `_soland` namespace — a
/// posture inversion the spec forbids ("private rail MUST NOT be weaker than the
/// protocol rail").
///
/// Until the rail either gains full per-request peer signature verification or
/// is folded into the protocol track, fail-close it outside deployment-local
/// mode so it is reachable only in the `development_mode` debug posture, matching
/// the read rail's stated "deployment-local test/ops affordance" intent and the
/// write rail's existing gate. The error mirrors the write rail's guidance.
pub(crate) fn ensure_private_inbound_read_rail_local(state: &AppState) -> Result<(), AppError> {
    if state.config().development_mode {
        return Ok(());
    }
    Err(AppError::unsupported_feature(
        "the /_soland/peer/federation/* inbound read rail is a deployment-local debug affordance \
         and is not authenticated to the protocol rail's standard; it is disabled outside \
         development mode. Use the protocol federation track (/_arkret/peer/*) for cross-deployment \
         reads",
    )
    .with_wire_code("federation_private_read_rail_local_only"))
}

/// SOL-02-007 / SOL-SEC-01 — federation actor↔origin binding, shared by both
/// inbound rails (the `/_arkret/peer/events` envelope track and the
/// `/_soland/peer/federation/*` operation track). Accept an inbound author when
/// its DID is hosted by the authenticated source service authority, or when the
/// actor is already present in the local membership index of the binding Realm
/// (the source service relays for a known member; proofs are still verified
/// downstream). A deployment trust domain is a ServiceDescribe claim and MUST
/// NOT be inferred from either DID's host. Converging both rails on this single
/// gate keeps the two surfaces from diverging again (SOL-DRY-01).
pub(crate) async fn federation_actor_origin_acceptable(
    state: &AppState,
    actor: &str,
    source_service_id: &str,
    binding_realm: &str,
) -> bool {
    if did_deployment_authority(actor).is_some()
        && did_deployment_authority(actor) == did_deployment_authority(source_service_id)
    {
        return true;
    }
    crate::routing::spaces::space::realm_has_member(state, binding_realm, actor).await
}

fn did_deployment_authority(did: &str) -> Option<String> {
    let authority = if let Some(rest) = did.strip_prefix("did:web:") {
        rest.split(':').next()?
    } else {
        let rest = did.strip_prefix("did:webvh:")?;
        let mut parts = rest.split(':');
        let scid = parts.next()?;
        if scid.is_empty() {
            return None;
        }
        parts.next()?
    };
    let authority = authority.trim_end_matches('.');
    (!authority.is_empty()).then(|| authority.to_ascii_lowercase())
}

pub(super) async fn enforce_inbound_operation_batch_policy(
    state: &AppState,
    origin_service_id: &str,
    operations: &[Operation],
) -> Result<(), AppError> {
    if operations.len() > MAX_INBOUND_FEDERATION_OPERATIONS {
        return Err(AppError::new(
            soland_http::error::ErrorCode::PayloadTooLarge,
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
        // SOL-SEC-01 — bind the operation's embedded actor DID to the origin
        // service authority before any side effect, so a verified peer cannot
        // speak for an unrelated actor that is not a known Realm member.
        if let Some(actor) = operation.actor()
            && !federation_actor_origin_acceptable(
                state,
                actor.as_str(),
                origin_service_id,
                operation.realm_id.as_str(),
            )
            .await
        {
            return Err(AppError::capability_denied(
                "operation actor home domain does not match the origin peer trust domain and \
                 the actor is not a known member of the target realm",
            )
            .with_wire_code("federation_actor_origin_rejected"));
        }
        enforce_realm_federation_policy(
            state,
            operation.realm_id.as_str(),
            origin_service_id,
            None,
            FederationDirection::Inbound,
        )?;
        enforce_realm_moderation_federation_policy(
            state,
            operation.realm_id.as_str(),
            origin_service_id,
            None,
            FederationDirection::Inbound,
        )?;
        let policy_actor = operation.actor();
        policy_gate::enforce_operation_policy_server(
            state,
            policy_actor
                .as_ref()
                .map(arkret_core::Did::as_str)
                .unwrap_or(origin_service_id),
            operation,
            PolicyGateSurface::FederationInbound {
                origin_service_id: origin_service_id.to_owned(),
            },
        )
        .await
        .map_err(app_error_from_policy_gate)?;
    }
    Ok(())
}

fn app_error_from_policy_gate(rejection: policy_gate::PolicyGateRejection) -> AppError {
    AppError::new(
        soland_http::error::ErrorCode::CapabilityDenied,
        rejection.message,
    )
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
        .projection_application()
        .snapshot()
        .realm_federation_policy(realm_id)
        .unwrap_or_else(|| "open".to_owned());
    // realm.schema.json federation_policy enum: ["open","restricted","closed",
    // "quarantine"] only. Any other value (incl. legacy mesh/hub/disabled) is
    // not spec-registered and fails closed.
    match policy.as_str() {
        "open" => Ok(()),
        "closed" => Err(
            AppError::capability_denied("realm federation_policy forbids federation")
                .with_wire_code("realm_federation_policy_closed"),
        ),
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
        .governance_application()
        .cached_realm_moderation_policy(realm_id);
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
        "server" | "service" | "service_id" | "peer" | "federation_peer" | "federation_server"
    );
    let did_matches = ["did", "service_id", "server_did", "peer_did", "target_did"]
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
        .settings()
        .federation_peers
        .iter()
        .filter_map(|entry| parse_peer_target(entry))
        .any(|peer| {
            peer.did == peer_did
                || peer_url
                    .is_some_and(|url| peer.url.trim_end_matches('/') == url.trim_end_matches('/'))
        })
}

#[cfg(test)]
mod tests {
    use super::did_deployment_authority;

    #[test]
    fn actor_origin_binding_preserves_encoded_development_port() {
        let actor = "did:webvh:zActor:127.0.0.1%3A3262:webvh:alice";
        let source = "did:webvh:zService:127.0.0.1%3a3262:webvh:service";
        let other = "did:webvh:zOther:127.0.0.1%3A3264:webvh:service";

        assert_eq!(
            did_deployment_authority(actor),
            did_deployment_authority(source)
        );
        assert_ne!(
            did_deployment_authority(actor),
            did_deployment_authority(other)
        );
    }

    #[test]
    fn actor_origin_binding_supports_did_web_and_rejects_non_hosted_methods() {
        assert_eq!(
            did_deployment_authority("did:web:EXAMPLE.com:alice"),
            Some("example.com".to_owned())
        );
        assert_eq!(did_deployment_authority("did:key:z6MkExample"), None);
    }
}
