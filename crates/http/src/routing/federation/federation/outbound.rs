use crate::state::AppState;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FederationPeerTarget {
    pub(crate) url: String,
    pub(crate) did: String,
    pub(crate) trust_domain: Option<String>,
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
        .find(|part| part.starts_with("did:"))?;
    let trust_domain = parts
        .iter()
        .copied()
        .find(|part| part.starts_with("ak:trust_domain:"));
    if parts.len() == 3 && trust_domain.is_none() {
        return None;
    }
    arkret_identifiers::Did::new(did.to_owned()).ok()?;
    if let Some(trust_domain) = trust_domain {
        arkret_identifiers::TypedTrustDomainId::new(trust_domain.to_owned()).ok()?;
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
            "https://peer.example|did:web:peer.example|ak:trust_domain:partner.example",
        )
        .expect("three-part peer target");
        assert_eq!(target.did, "did:web:peer.example");
        assert_eq!(
            target.trust_domain.as_deref(),
            Some("ak:trust_domain:partner.example")
        );
        assert!(
            parse_peer_target("https://peer.example|did:web:peer.example|not-a-trust-domain")
                .is_none()
        );
    }
}
