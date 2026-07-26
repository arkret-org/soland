use crate::state::AppState;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FederationPeerTarget {
    pub(crate) url: String,
    pub(crate) did: String,
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
            }
            !denied
        })
        .collect()
}

pub(crate) fn peer_url_for_service_id(state: &AppState, service_id: &str) -> Option<String> {
    configured_peer_targets(state)
        .into_iter()
        .find(|peer| peer.did == service_id)
        .map(|peer| peer.url)
}

pub(super) fn parse_peer_target(entry: &str) -> Option<FederationPeerTarget> {
    let entry = entry.trim();
    if entry.is_empty() {
        return None;
    }
    let (left, right) = entry
        .split_once('|')
        .map(|(left, right)| (left.trim(), right.trim()))
        .unwrap_or((entry, entry));
    if left.is_empty() || right.is_empty() {
        return None;
    }
    let (url, did) = if left.starts_with("did:") && !right.starts_with("did:") {
        (right, left)
    } else if right.starts_with("did:") && !left.starts_with("did:") {
        (left, right)
    } else {
        return None;
    };
    arkret_identifiers::Did::new(did.to_owned()).ok()?;
    Some(FederationPeerTarget {
        url: url.trim_end_matches('/').to_owned(),
        did: did.to_owned(),
    })
}
