use crate::state::AppState;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FederationPeerTarget {
    pub(crate) url: String,
    pub(crate) did: String,
    pub(crate) trust_domain: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedFederationPeerTarget {
    pub(crate) base_url: String,
    pub(crate) trust_domain: String,
}

pub(crate) fn configured_peer_targets(state: &AppState) -> Vec<FederationPeerTarget> {
    use crate::config::FederationFanoutTopology;
    let settings = state.settings();
    let entries: Vec<String> = match settings.federation_fanout_topology {
        FederationFanoutTopology::Mesh => settings.federation_peers.clone(),
        FederationFanoutTopology::Hub => settings
            .federation_peers
            .first()
            .cloned()
            .into_iter()
            .collect(),
    };
    entries
        .into_iter()
        .filter_map(|entry| parse_peer_target(&entry))
        .filter(|peer| {
            let denied = crate::security::federation_peer_denied(&peer.url, &peer.did);
            if denied {
                tracing::warn!(
                    peer_url = %peer.url,
                    peer_did = %peer.did,
                    "configured federation peer denied by deployment peer policy"
                );
                return false;
            }
            // `sovereign-deployment.md` §8 — a sovereign deployment MUST check
            // the target service_id's trust_domain against the local
            // federation_allowlist before the request, and MUST NOT rely on
            // the receiver to refuse. The denylist above cannot express this:
            // it fails open on anything it was not told about.
            if let Some(reason) = crate::security::federation_outbound_trust_domain_denial(
                &peer.did,
                peer.trust_domain.as_deref(),
            ) {
                tracing::warn!(
                    peer_url = %peer.url,
                    peer_did = %peer.did,
                    %reason,
                    "configured federation peer denied by sovereign outbound trust_domain policy"
                );
                return false;
            }
            true
        })
        .collect()
}

pub(crate) fn peer_url_for_service_id(state: &AppState, service_id: &str) -> Option<String> {
    configured_peer_targets(state)
        .into_iter()
        .find(|peer| peer.did == service_id)
        .map(|peer| peer.url)
}

/// Resolve a service destination through the shared verified resolver.
pub(crate) async fn resolved_peer_base_url(
    state: &AppState,
    service_id: &str,
    service_kind: &str,
    force_refresh: bool,
) -> Result<String, String> {
    Ok(
        resolved_peer_target(state, service_id, service_kind, force_refresh)
            .await?
            .base_url,
    )
}

/// Resolve the exact routable URL and destination trust domain from the same
/// independently verified record→ServiceDescribe chain. A configured trust
/// domain, when present, is only an additional accepted-binding constraint and
/// must agree with the fetched description.
pub(crate) async fn resolved_peer_target(
    state: &AppState,
    service_id: &str,
    service_kind: &str,
    force_refresh: bool,
) -> Result<ResolvedFederationPeerTarget, String> {
    let route = resolved_peer_route(state, service_id, service_kind, force_refresh).await?;
    Ok(ResolvedFederationPeerTarget {
        base_url: route.cache_entry.base_url.trim_end_matches('/').to_owned(),
        trust_domain: route.trust_domain.to_string(),
    })
}

/// Resolve a core service id to the complete independently verified
/// record→ServiceDescribe result. Callers that sign protocol requests should
/// retain this value so the endpoint and trust domain come from one snapshot.
pub(crate) async fn resolved_peer_route(
    state: &AppState,
    service_id: &str,
    service_kind: &str,
    force_refresh: bool,
) -> Result<soland_services::service_route::ResolvedServiceRoute, String> {
    let core = arkret_wire::DidCoreId::new(service_id.to_owned())
        .map_err(|error| format!("federation destination is not a service core id: {error}"))?;
    let route = state
        .service_route_resolver()
        .map_err(str::to_owned)?
        .resolve_route(&core, service_kind, chrono::Utc::now(), force_refresh)
        .await
        .map_err(|error| error.to_string())?;
    route
        .require_trust_domain(peer_trust_domain_for_service_id(state, service_id).as_deref())
        .map_err(|error| error.to_string())?;
    Ok(route)
}

pub(crate) fn peer_trust_domain_for_service_id(
    state: &AppState,
    service_id: &str,
) -> Option<String> {
    state
        .settings()
        .federation_peers
        .iter()
        .filter_map(|entry| parse_peer_target(entry))
        .find(|peer| peer.did == service_id)
        .and_then(|peer| peer.trust_domain)
}

pub(super) fn parse_peer_target(entry: &str) -> Option<FederationPeerTarget> {
    let entry = entry.trim();
    if entry.is_empty() {
        return None;
    }
    let parts = entry.split('|').map(str::trim).collect::<Vec<_>>();
    if parts.iter().any(|part| part.is_empty()) || !(2..=3).contains(&parts.len()) {
        return None;
    }
    let url = parts
        .iter()
        .copied()
        .find(|part| part.starts_with("https://") || part.starts_with("http://"))?;
    let did = parts
        .iter()
        .copied()
        .find(|part| arkret_wire::DidCoreId::new((*part).to_owned()).is_ok())?;
    let trust_domain = parts
        .iter()
        .copied()
        .find(|part| part.starts_with("ak:trust_domain:"));
    if parts.len() == 3 && trust_domain.is_none() {
        return None;
    }
    if arkret_wire::DidCoreId::new(did.to_owned()).is_err() {
        return None;
    }
    if let Some(trust_domain) = trust_domain {
        arkret_identifiers::TrustDomainId::new(trust_domain.to_owned()).ok()?;
    }
    Some(FederationPeerTarget {
        url: url.trim_end_matches('/').to_owned(),
        did: did.to_owned(),
        trust_domain: trust_domain.map(ToOwned::to_owned),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_target_preserves_verified_trust_domain_binding() {
        let target = parse_peer_target(
            "https://peer.example|ak:did_core:web:peer.example|ak:trust_domain:partner.example",
        )
        .expect("three-part peer target");
        assert_eq!(target.did, "ak:did_core:web:peer.example");
        assert_eq!(
            target.trust_domain.as_deref(),
            Some("ak:trust_domain:partner.example")
        );
        assert!(
            parse_peer_target(
                "https://peer.example|ak:did_core:web:peer.example|not-a-trust-domain"
            )
            .is_none()
        );
        let core = parse_peer_target(
            "https://peer.example|ak:did_core:webvh:z6mkpeer|ak:trust_domain:partner.example",
        )
        .expect("core service target");
        assert_eq!(core.did, "ak:did_core:webvh:z6mkpeer");
    }
}
