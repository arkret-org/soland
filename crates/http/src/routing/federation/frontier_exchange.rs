use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::Signer as _;
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue};
use soland_services::events::CanonicalEventRecord;
use soland_services::federation::FEDERATION_FRONTIER_STATUS_STALE_PEER;

use crate::state::AppState;

const EXCHANGE_INTERVAL: Duration = Duration::from_secs(60 * 60);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub fn spawn(state: AppState) -> Option<Arc<tokio::task::JoinHandle<()>>> {
    if !state.config().federation_outbound_enabled {
        return None;
    }
    Some(FrontierExchangeWorker::new(state).spawn())
}

pub struct FrontierExchangeWorker {
    state: AppState,
}

impl FrontierExchangeWorker {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    pub fn spawn(self) -> Arc<tokio::task::JoinHandle<()>> {
        let task = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(EXCHANGE_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                if let Err(error) = self.run_one_pass().await {
                    tracing::warn!(
                        %error,
                        worker = "federation_frontier_exchange",
                        "frontier exchange pass failed"
                    );
                }
            }
        });
        Arc::new(task)
    }

    pub async fn run_one_pass(&self) -> Result<(), String> {
        let peers = super::federation::configured_peer_targets(&self.state);
        if peers.is_empty() {
            return Ok(());
        }
        let records = self
            .state
            .event_queries()
            .canonical_events()
            .await
            .map_err(|error| error.to_string())?;
        let realms = federation_visible_realms(&records);
        for realm_id in realms {
            let local_root = match local_frontier_root(&records, &realm_id) {
                Ok(root) => root,
                Err(error) => {
                    tracing::warn!(
                        %error,
                        realm_id,
                        worker = "federation_frontier_exchange",
                        "local frontier root could not be computed"
                    );
                    continue;
                }
            };
            for peer in &peers {
                if peer.did == *self.state.service_id() {
                    continue;
                }
                let result = self.probe_peer(&peer.url, &peer.did, &realm_id).await;
                let now = chrono::Utc::now().timestamp();
                match result {
                    Ok(remote_root) if remote_root == local_root => {
                        let record = self
                            .state
                            .federation()
                            .record_frontier_success(&realm_id, &peer.did, &remote_root, now)
                            .await
                            .map_err(|error| error.to_string())?;
                        tracing::debug!(
                            realm_id,
                            peer_service_id = %peer.did,
                            status = %record.status,
                            worker = "federation_frontier_exchange",
                            "frontier exchange succeeded"
                        );
                    }
                    Ok(remote_root) => {
                        self.record_failure(
                            &realm_id,
                            &peer.did,
                            "frontier_root_mismatch",
                            now,
                            Some(&remote_root),
                        )
                        .await?;
                    }
                    Err(error) => {
                        self.record_failure(&realm_id, &peer.did, &error, now, None)
                            .await?;
                    }
                }
            }
        }
        Ok(())
    }

    async fn probe_peer(
        &self,
        peer_url: &str,
        peer_did: &str,
        realm_id: &str,
    ) -> Result<String, String> {
        let canonical_target = format!(
            "{}/_arkret/peer/events/frontier",
            peer_url.trim_end_matches('/')
        );
        let request = arkret_models_collaboration::event_query::PeerEventsFrontierRequestBody {
            realm_id: arkret_identifiers::RealmId::new(realm_id.to_owned())
                .map_err(|error| format!("invalid_realm_id:{error}"))?,
        };
        let body = arkret_canonical::canonical_json_bytes(&request)
            .map_err(|error| format!("canonical_json:{error}"))?;
        let (parsed_url, client) =
            crate::security::validate_http_url_for_egress_with_pinned_client(
                &canonical_target,
                "federation frontier exchange",
                self.state.config().development_mode,
                REQUEST_TIMEOUT,
            )
            .map_err(|error| format!("egress_policy_denied:{error}"))?;
        let headers = signed_query_headers(&self.state, peer_did, &canonical_target, &body);
        let query_method = reqwest::Method::from_bytes(b"QUERY")
            .map_err(|error| format!("invalid_query_method:{error}"))?;
        let mut response = client
            .request(query_method, parsed_url)
            .headers(headers)
            .body(body)
            .send()
            .await
            .map_err(|error| format!("network_error:{error}"))?;
        if matches!(response.status().as_u16(), 405 | 501) {
            let mut fallback_url = reqwest::Url::parse(&canonical_target)
                .map_err(|error| format!("invalid_peer_url:{error}"))?;
            fallback_url
                .query_pairs_mut()
                .append_pair("realm_id", realm_id);
            let fallback_target = fallback_url.as_str().to_owned();
            let (parsed_url, fallback_client) =
                crate::security::validate_http_url_for_egress_with_pinned_client(
                    &fallback_target,
                    "federation frontier exchange compatibility GET",
                    self.state.config().development_mode,
                    REQUEST_TIMEOUT,
                )
                .map_err(|error| format!("egress_policy_denied:{error}"))?;
            let headers = signed_get_headers(&self.state, peer_did, &fallback_target);
            response = fallback_client
                .get(parsed_url)
                .headers(headers)
                .send()
                .await
                .map_err(|error| format!("network_error:{error}"))?;
        }
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(format!("http_status:{}", status.as_u16()));
        }
        let state: arkret_models_collaboration::event_sync::EventsFrontierFederationPeerState =
            serde_json::from_str(&body).map_err(|_| "bad_json".to_owned())?;
        validate_frontier_response(&state, peer_did, realm_id)
    }

    async fn record_failure(
        &self,
        realm_id: &str,
        peer_did: &str,
        reason: &str,
        observed_at: i64,
        remote_root: Option<&str>,
    ) -> Result<(), String> {
        let record = self
            .state
            .federation()
            .record_frontier_failure(realm_id, peer_did, reason, observed_at)
            .await
            .map_err(|error| error.to_string())?;
        if record.status == FEDERATION_FRONTIER_STATUS_STALE_PEER {
            tracing::error!(
                realm_id,
                peer_service_id = %peer_did,
                consecutive_failures = record.consecutive_failures,
                reason,
                remote_frontier_root = remote_root.unwrap_or(""),
                worker = "federation_frontier_exchange",
                "federation peer marked stale_peer; inbound push will fail closed"
            );
        } else {
            tracing::warn!(
                realm_id,
                peer_service_id = %peer_did,
                consecutive_failures = record.consecutive_failures,
                reason,
                worker = "federation_frontier_exchange",
                "frontier exchange failed"
            );
        }
        Ok(())
    }
}

fn signed_query_headers(
    state: &AppState,
    peer_did: &str,
    target_url: &str,
    body: &[u8],
) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    super::outbox::insert_header_if_valid(
        &mut headers,
        "content-digest",
        &super::outbox::content_digest_header_value(body),
    );
    super::outbox::insert_header_if_valid(&mut headers, "source-service-id", state.service_id());
    super::outbox::insert_header_if_valid(&mut headers, "destination-service-id", peer_did);
    super::outbox::insert_header_if_valid(
        &mut headers,
        "source-trust-domain",
        &state.config().trust_domain,
    );
    super::outbox::insert_header_if_valid(
        &mut headers,
        "destination-trust-domain",
        &super::federation::trust_domain_from_service_id(peer_did),
    );
    super::outbox::rfc9421_sign(state, headers, "QUERY", target_url)
}

fn signed_get_headers(state: &AppState, peer_did: &str, target_url: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    insert_header(&mut headers, "source-service-id", state.service_id());
    insert_header(&mut headers, "destination-service-id", peer_did);
    insert_header(
        &mut headers,
        "source-trust-domain",
        &state.config().trust_domain,
    );
    insert_header(
        &mut headers,
        "destination-trust-domain",
        &super::federation::trust_domain_from_service_id(peer_did),
    );

    let created = chrono::Utc::now().timestamp();
    let expires = created + 300;
    let keyid = super::federation_service_signature_key_id(state.service_id());
    let covered = [
        "\"@method\"",
        "\"@target-uri\"",
        "\"@authority\"",
        "\"source-service-id\"",
        "\"destination-service-id\"",
        "\"source-trust-domain\"",
        "\"destination-trust-domain\"",
    ]
    .join(" ");
    let signature_params = format!(
        "({covered});created={created};expires={expires};keyid=\"{keyid}\";alg=\"ed25519\"",
    );
    let authority = authority_from_target_url(target_url);
    let signature_base = format!(
        "\"@method\": GET\n\
         \"@target-uri\": {target_url}\n\
         \"@authority\": {authority}\n\
         \"source-service-id\": {}\n\
         \"destination-service-id\": {}\n\
         \"source-trust-domain\": {}\n\
         \"destination-trust-domain\": {}\n\
         \"@signature-params\": {signature_params}",
        header_value(&headers, "source-service-id").unwrap_or_default(),
        header_value(&headers, "destination-service-id").unwrap_or_default(),
        header_value(&headers, "source-trust-domain").unwrap_or_default(),
        header_value(&headers, "destination-trust-domain").unwrap_or_default(),
    );
    let signature = state.notary_signing_key().sign(signature_base.as_bytes());
    insert_header(
        &mut headers,
        "signature-input",
        &format!("sig1={signature_params}"),
    );
    insert_header(
        &mut headers,
        "signature",
        &format!("sig1=:{}:", STANDARD.encode(signature.to_bytes())),
    );
    headers
}

fn insert_header(headers: &mut HeaderMap, name: &'static str, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        headers.insert(name, value);
    }
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
}

fn authority_from_target_url(target_url: &str) -> String {
    let Ok(url) = reqwest::Url::parse(target_url) else {
        return String::new();
    };
    let Some(host) = url.host_str() else {
        return String::new();
    };
    url.port()
        .map(|port| format!("{host}:{port}"))
        .unwrap_or_else(|| host.to_owned())
}

fn federation_visible_realms(records: &[CanonicalEventRecord]) -> BTreeSet<String> {
    records
        .iter()
        .filter_map(crate::routing::events::event_log::canonical_realm_id_for_record)
        .collect()
}

fn local_frontier_root(records: &[CanonicalEventRecord], realm_id: &str) -> Result<String, String> {
    let visible_realm_records = records
        .iter()
        .filter(|record| {
            crate::routing::events::event_log::canonical_realm_id_for_record(record).as_deref()
                == Some(realm_id)
        })
        .collect::<Vec<_>>();
    let mut actor_frontier: BTreeMap<String, u64> = BTreeMap::new();
    for record in &visible_realm_records {
        actor_frontier
            .entry(record.actor_id.clone())
            .and_modify(|seq| *seq = (*seq).max(record.actor_seq))
            .or_insert(record.actor_seq);
    }
    let mut heads = visible_realm_records
        .iter()
        .filter(|record| {
            actor_frontier
                .get(record.actor_id.as_str())
                .is_some_and(|seq| *seq == record.actor_seq)
        })
        .map(|record| record.event_id.clone())
        .collect::<Vec<_>>();
    heads.sort();
    heads.dedup();
    let realm_frontier =
        crate::routing::events::frontier::typed_realm_frontier([(realm_id.to_owned(), heads)]);
    let actor_bounds = crate::routing::events::frontier::typed_actor_upper_bounds(actor_frontier);
    crate::routing::events::frontier::frontier_root(&realm_frontier, &actor_bounds)
        .map(|root| root.to_string())
}

fn validate_frontier_response(
    state: &arkret_models_collaboration::event_sync::EventsFrontierFederationPeerState,
    peer_did: &str,
    realm_id: &str,
) -> Result<String, String> {
    if state.realm_id.as_str() != realm_id {
        return Err("realm_id_mismatch".to_owned());
    }
    if state.issuer.as_str() != peer_did {
        return Err("issuer_mismatch".to_owned());
    }
    if state.signature.is_empty() {
        return Err("signature_missing".to_owned());
    }
    Ok(state.frontier_root.to_string())
}

pub async fn inbound_peer_is_stale(
    state: &AppState,
    realm_id: &str,
    peer_service_id: &str,
) -> Result<bool, String> {
    state
        .federation()
        .frontier_exchange(realm_id, peer_service_id)
        .await
        .map(|record| {
            record.is_some_and(|record| record.status == FEDERATION_FRONTIER_STATUS_STALE_PEER)
        })
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frontier_response_validation_requires_bound_peer_and_realm() {
        let body = serde_json::json!({
            "realm_id": "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K",
            "heads": [],
            "issuer": "did:web:peer.example",
            "frontier_root": format!("sha256:{}", "a".repeat(64)),
            "observed_at": "2026-01-01T00:00:00.000Z",
            "signature": {"value": "c2ln"}
        });
        let state: arkret_models_collaboration::event_sync::EventsFrontierFederationPeerState =
            serde_json::from_value(body).expect("valid peer state fixture");
        assert!(
            validate_frontier_response(
                &state,
                "did:web:peer.example",
                "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K"
            )
            .is_ok()
        );
        assert_eq!(
            validate_frontier_response(
                &state,
                "did:web:other.example",
                "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K"
            )
            .unwrap_err(),
            "issuer_mismatch"
        );
    }
}
