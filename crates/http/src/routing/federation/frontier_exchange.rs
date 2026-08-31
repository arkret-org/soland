use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use arkret_models_collaboration::event_sync::EventsFrontierFederationPeerState;
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue};
use soland_services::events::AcceptedEvent;
use soland_services::federation::FEDERATION_FRONTIER_STATUS_PEER_STALE;

use super::frontier_reduction::{self, ReductionPlan};
use crate::state::AppState;

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
            let mut ticker = tokio::time::interval(Duration::from_secs(
                self.state.config().federation_frontier_interval_seconds,
            ));
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
            for peer in &peers {
                if peer.service_id.as_str() == self.state.service_id() {
                    continue;
                }
                let result = self.exchange_peer(&peer.service_id, &realm_id).await;
                let now = chrono::Utc::now().timestamp();
                match result {
                    Ok(Some(remote_root)) => {
                        let record = self
                            .state
                            .federation()
                            .record_frontier_success(&realm_id, &peer.service_id, &remote_root, now)
                            .await
                            .map_err(|error| error.to_string())?;
                        tracing::debug!(
                            realm_id,
                            peer_id = %peer.service_id,
                            status = %record.status,
                            worker = "federation_frontier_exchange",
                            "frontier exchange succeeded"
                        );
                    }
                    Ok(None) => {}
                    Err(error) => {
                        self.record_failure(&realm_id, &peer.service_id, &error, now, None)
                            .await?;
                    }
                }
            }
        }
        Ok(())
    }

    async fn exchange_peer(
        &self,
        peer_id: &arkret_wire::DidCoreId,
        realm_id: &str,
    ) -> Result<Option<String>, String> {
        let existing = self
            .state
            .federation()
            .frontier_exchange(realm_id, peer_id)
            .await
            .map_err(|error| error.to_string())?;
        if existing
            .as_ref()
            .and_then(|record| record.last_error.as_deref())
            .is_some_and(|reason| matches!(reason, "witness_disagreement" | "fork_quarantine"))
        {
            // Availability is not an authorized resolution of retained evidence.
            // Do not admit another increment through the backfill recovery rail.
            return Ok(None);
        }
        for _ in 0..3 {
            let before = self
                .state
                .event_queries()
                .canonical_events()
                .await
                .map_err(|error| error.to_string())?;
            let (visible, required) = crate::routing::events::peer::frontier_disclosure_snapshot(
                &self.state,
                peer_id.as_str(),
                realm_id,
                &before,
            )
            .await
            .map_err(|error| error.to_string())?;
            let remote = self.probe_peer(peer_id, realm_id).await?;
            match frontier_reduction::plan(&before, &visible, &remote, &required)? {
                ReductionPlan::Equal | ReductionPlan::Disjoint => {
                    return Ok(Some(remote.frontier_root.to_string()));
                }
                ReductionPlan::Challenge(actors) => {
                    let admitted = match self.challenge(peer_id, &remote, &actors).await {
                        Ok(admitted) => admitted,
                        Err(error)
                            if matches!(
                                error.as_str(),
                                "temporarily_unavailable:challenge_page_budget"
                                    | "temporarily_unavailable:challenge_byte_budget"
                                    | "temporarily_unavailable:dependency_budget"
                                    | "temporarily_unavailable:admission_round_budget"
                                    | "temporarily_unavailable:backfill_publication_evidence_unavailable"
                            ) =>
                        {
                            // Local resource or evidence-acquisition limits
                            // do not establish a peer validation failure.
                            tracing::debug!(realm_id, peer_id = %peer_id, reason = %error, "frontier reduction deferred pending resources or publication evidence");
                            return Ok(None);
                        }
                        Err(error) => return Err(error),
                    };
                    let after = self
                        .state
                        .event_queries()
                        .canonical_events()
                        .await
                        .map_err(|error| error.to_string())?;
                    if frontier_reduction::snapshot_changed(&before, &after, &admitted, realm_id) {
                        continue;
                    }
                    let actor_keys = actors.iter().map(ToString::to_string).collect();
                    let sets = frontier_reduction::sibling_sets(&after, realm_id, &actor_keys)?;
                    tracing::debug!(realm_id, peer_id = %peer_id, positions = sets.len(), "frontier sibling reduction completed without a completeness claim");
                    return Ok(Some(remote.frontier_root.to_string()));
                }
            }
        }
        // Local concurrency exhausted this pass's budget. Retry on the next
        // scheduled pass without charging a failure to an honest remote peer.
        Ok(None)
    }

    async fn peer_query<T: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        peer_id: &arkret_wire::DidCoreId,
        path: &str,
        request: &T,
    ) -> Result<(R, String, usize), String> {
        let route =
            super::federation::resolved_peer_route(&self.state, peer_id.as_str(), "station", false)
                .await
                .map_err(|error| format!("service_route_unavailable:{error}"))?;
        if let Some(reason) = crate::security::federation_outbound_trust_domain_denial(
            peer_id.as_str(),
            Some(route.trust_domain.as_str()),
        ) {
            return Err(format!("trust_domain_policy_denied:{reason}"));
        }
        let target = format!(
            "{}{}",
            route.cache_entry.base_url.trim_end_matches('/'),
            path
        );
        let body =
            arkret_canonical::canonical_json_bytes(request).map_err(|error| error.to_string())?;
        let (url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
            &target,
            "federation frontier reduction",
            self.state.config().development_mode,
            REQUEST_TIMEOUT,
        )
        .map_err(|error| error.to_string())?;
        let headers = signed_query_headers(
            &self.state,
            peer_id.as_str(),
            route.trust_domain.as_str(),
            &target,
            &body,
        );
        let mut response = client
            .request(
                reqwest::Method::from_bytes(b"QUERY").map_err(|error| error.to_string())?,
                url,
            )
            .headers(headers)
            .body(body)
            .send()
            .await
            .map_err(|error| format!("network_error:{error}"))?;
        if !response.status().is_success() {
            return Err(format!("http_status:{}", response.status().as_u16()));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| format!("network_error:{error}"))?
        {
            if bytes.len() + chunk.len() > 8 * 1024 * 1024 {
                return Err("schema_violation:response_byte_limit".to_owned());
            }
            bytes.extend_from_slice(&chunk);
        }
        let value =
            serde_json::from_slice(&bytes).map_err(|error| format!("schema_violation:{error}"))?;
        Ok((value, route.trust_domain.to_string(), bytes.len()))
    }

    async fn challenge(
        &self,
        peer_id: &arkret_wire::DidCoreId,
        remote: &EventsFrontierFederationPeerState,
        actors: &[arkret_wire::ActorId],
    ) -> Result<BTreeSet<String>, String> {
        use arkret_models_collaboration::event_query::EventsQueryPostRequestBody;
        use arkret_models_collaboration::http_bodies::{
            EventsQueryOutcome, PeerEventsResolveOutcome, PeerEventsResolveRequestBody,
        };
        let actor_set = actors.iter().cloned().collect::<BTreeSet<_>>();
        let mut pending = Vec::new();
        let mut bytes = 0;
        let mut pages = 0;
        let mut trust_domain = String::new();
        for actor in actors {
            let mut cursor = None;
            let mut cursors = BTreeSet::new();
            loop {
                pages += 1;
                if pages > 64 {
                    return Err("temporarily_unavailable:challenge_page_budget".to_owned());
                }
                let request = EventsQueryPostRequestBody {
                    realm_ids: vec![remote.realm_id.clone()],
                    actor_ids: vec![actor.clone()],
                    after: cursor.clone(),
                    order: Some("ascending".to_owned()),
                    limit: Some(256),
                    ..Default::default()
                };
                let (page, domain, size): (EventsQueryOutcome, _, _) = self
                    .peer_query(peer_id, "/_arkret/peer/events", &request)
                    .await?;
                trust_domain = domain;
                bytes += size;
                if bytes > 64 * 1024 * 1024 {
                    return Err("temporarily_unavailable:challenge_byte_budget".to_owned());
                }
                for row in page.events {
                    let event = row.into_event().ok_or_else(|| {
                        "schema_violation:challenge_requires_full_event".to_owned()
                    })?;
                    if event.realm_id != remote.realm_id || event.actor_id != *actor {
                        return Err("schema_violation:challenge_selector_mismatch".to_owned());
                    }
                    pending.push(event);
                }
                if !page.has_more {
                    break;
                }
                let next = page
                    .next_cursor
                    .ok_or_else(|| "schema_violation:missing_scan_cursor".to_owned())?;
                if !cursors.insert(next.clone()) {
                    return Err("schema_violation:repeated_scan_cursor".to_owned());
                }
                cursor = Some(arkret_wire::Cursor::new(next).map_err(|error| error.to_string())?);
            }
        }
        // Resolve advertised heads, then verified predecessor dependencies.
        // A finite selector and byte budget bounds even adversarial DAGs.
        let mut selectors = remote.head_ids.iter().cloned().collect::<BTreeSet<_>>();
        let mut dependencies = BTreeSet::new();
        let mut resolved = BTreeSet::new();
        let mut admitted = BTreeSet::new();
        let mut dependency_closure_complete = false;
        for _ in 0..64 {
            for event in &pending {
                crate::routing::events::event_log::verify_frontier_backfill_event(
                    &self.state,
                    event,
                )
                .await?;
                resolved.insert(event.event_id.clone());
                if actor_set.contains(&event.actor_id) || dependencies.contains(&event.event_id) {
                    dependencies.extend(event.prev_refs.iter().cloned());
                    selectors.extend(event.prev_refs.iter().cloned());
                }
            }
            selectors.retain(|id| !resolved.contains(id));
            if selectors.len() > 16_384 {
                return Err("temporarily_unavailable:dependency_budget".to_owned());
            }
            let mut missing = Vec::new();
            for id in &selectors {
                if self
                    .state
                    .event_queries()
                    .canonical_event(id.as_str())
                    .await
                    .map_err(|error| error.to_string())?
                    .is_none()
                {
                    missing.push(id.clone());
                } else {
                    resolved.insert(id.clone());
                }
            }
            if missing.is_empty() {
                dependency_closure_complete = true;
                break;
            }
            for batch in missing.chunks(256) {
                let request = PeerEventsResolveRequestBody {
                    realm_id: remote.realm_id.clone(),
                    event_ids: batch.to_vec(),
                    event_digests: Vec::new(),
                    include_payload: Some(true),
                    max_response_bytes: Some(8 * 1024 * 1024),
                    history_traversal_access: None,
                };
                let (outcome, domain, size): (PeerEventsResolveOutcome, _, _) = self
                    .peer_query(peer_id, "/_arkret/peer/events/resolve", &request)
                    .await?;
                trust_domain = domain;
                bytes += size;
                pages += 1;
                if pages > 128 || bytes > 64 * 1024 * 1024 {
                    return Err("temporarily_unavailable:dependency_budget".to_owned());
                }
                for event in &outcome.events {
                    crate::routing::events::event_log::verify_frontier_backfill_event(
                        &self.state,
                        event,
                    )
                    .await?;
                }
                outcome
                    .validate_for_request(&request)
                    .map_err(|error| format!("schema_violation:{error}"))?;
                if !outcome.missing_event_ids.is_empty()
                    || !outcome.missing_event_digests.is_empty()
                {
                    return Err("dependency_missing:advertised_head_or_predecessor".to_owned());
                }
                if outcome
                    .events
                    .iter()
                    .any(|event| event.realm_id != remote.realm_id)
                {
                    return Err("schema_violation:dependency_realm_mismatch".to_owned());
                }
                pending.extend(outcome.events);
            }
        }
        if !dependency_closure_complete {
            return Err("temporarily_unavailable:dependency_budget".to_owned());
        }
        // Dependencies can precede the actor intersection, but unrelated heads
        // never expand the replication obligation of this exchange.
        for actor in actors {
            let upper = remote.actor_seq_upper_bounds[actor];
            if !pending
                .iter()
                .any(|event| event.actor_id == *actor && event.actor_seq == upper)
            {
                return Err("schema_violation:advertised_actor_bound_not_disclosed".to_owned());
            }
        }
        pending.retain(|event| {
            actor_set.contains(&event.actor_id) || dependencies.contains(&event.event_id)
        });
        pending.sort_by(|a, b| (a.actor_seq, &a.event_id).cmp(&(b.actor_seq, &b.event_id)));
        for _ in 0..64 {
            if pending.is_empty() {
                return Ok(admitted);
            }
            let mut retry = Vec::new();
            let mut progress = false;
            for event in pending {
                match crate::routing::events::event_log::admit_frontier_backfill_event(
                    &self.state,
                    peer_id.as_str(),
                    &trust_domain,
                    &event,
                )
                .await
                {
                    Ok(_) => {
                        admitted.insert(event.event_id.to_string());
                        progress = true;
                    }
                    Err(error) if error.code == "dependency_missing" => retry.push(event),
                    Err(error) => {
                        if error.quarantine_event_id.is_some() {
                            return Err(error.code);
                        }
                        return Err(format!("{}:{}", error.code, error.message));
                    }
                }
            }
            if !progress {
                return Err("dependency_missing:backfill_admission".to_owned());
            }
            pending = retry;
        }
        Err("temporarily_unavailable:admission_round_budget".to_owned())
    }

    async fn probe_peer(
        &self,
        peer_id: &arkret_wire::DidCoreId,
        realm_id: &str,
    ) -> Result<EventsFrontierFederationPeerState, String> {
        let route =
            super::federation::resolved_peer_route(&self.state, peer_id.as_str(), "station", false)
                .await
                .map_err(|error| format!("service_route_unavailable:{error}"))?;
        if let Some(reason) = crate::security::federation_outbound_trust_domain_denial(
            peer_id.as_str(),
            Some(route.trust_domain.as_str()),
        ) {
            return Err(format!("trust_domain_policy_denied:{reason}"));
        }
        let request = arkret_models_collaboration::event_query::PeerEventsFrontierRequestBody {
            realm_id: arkret_identifiers::RealmId::new(realm_id.to_owned())
                .map_err(|error| format!("invalid_realm_id:{error}"))?,
            actor_id: None,
        };
        let (state, ..): (EventsFrontierFederationPeerState, _, _) = self
            .peer_query(peer_id, "/_arkret/peer/events/frontier", &request)
            .await?;
        if state.auth_state_root.is_some()
            || state.policy_frontier_root.is_some()
            || state.membership_frontier_root.is_some()
        {
            return Err("unexpected_actor_frontier_roots".to_owned());
        }
        let document =
            crate::jws_verify::resolve_did_document_async(&self.state, &route.cache_entry.did)
                .await?;
        let result = validate_frontier_response(
            &state,
            peer_id.as_str(),
            realm_id,
            chrono::Utc::now(),
            &document,
        );
        if result.is_ok() {
            return Ok(state);
        }
        // A key miss or rotation must refresh the verified route and authority
        // document, never retry against a service-id-only cached public key.
        let refreshed =
            super::federation::resolved_peer_route(&self.state, peer_id.as_str(), "station", true)
                .await?;
        let document =
            crate::jws_verify::resolve_did_document_async(&self.state, &refreshed.cache_entry.did)
                .await?;
        validate_frontier_response(
            &state,
            peer_id.as_str(),
            realm_id,
            chrono::Utc::now(),
            &document,
        )?;
        Ok(state)
    }

    async fn record_failure(
        &self,
        realm_id: &str,
        peer_id: &arkret_wire::DidCoreId,
        reason: &str,
        observed_at: i64,
        remote_root: Option<&str>,
    ) -> Result<(), String> {
        let record = self
            .state
            .federation()
            .record_frontier_failure(realm_id, peer_id, reason, observed_at)
            .await
            .map_err(|error| error.to_string())?;
        if record.status == FEDERATION_FRONTIER_STATUS_PEER_STALE {
            tracing::error!(
                realm_id,
                peer_id = %peer_id,
                consecutive_failures = record.consecutive_failures,
                reason,
                remote_frontier_root = remote_root.unwrap_or(""),
                worker = "federation_frontier_exchange",
                "federation peer marked peer_stale; inbound push will fail closed"
            );
        } else {
            tracing::warn!(
                realm_id,
                peer_id = %peer_id,
                consecutive_failures = record.consecutive_failures,
                reason,
                worker = "federation_frontier_exchange",
                "frontier exchange failed"
            );
        }
        Ok(())
    }
}

pub(crate) fn signed_query_headers(
    state: &AppState,
    peer_id: &str,
    peer_trust_domain: &str,
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
    insert_destination_binding(&mut headers, peer_id, peer_trust_domain);
    super::outbox::insert_header_if_valid(
        &mut headers,
        "source-trust-domain",
        state.config().trust_domain.as_str(),
    );
    super::outbox::rfc9421_sign(state, headers, "QUERY", target_url)
}

fn insert_destination_binding(headers: &mut HeaderMap, peer_id: &str, verified_trust_domain: &str) {
    insert_header(headers, "destination-service-id", peer_id);
    insert_header(headers, "destination-trust-domain", verified_trust_domain);
}

fn insert_header(headers: &mut HeaderMap, name: &'static str, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        headers.insert(name, value);
    }
}

#[cfg(test)]
fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
}

fn federation_visible_realms(records: &[AcceptedEvent]) -> BTreeSet<String> {
    records
        .iter()
        .filter_map(crate::routing::events::event_log::canonical_realm_id_for_record)
        .collect()
}

pub(super) fn local_frontier_root(
    records: &[AcceptedEvent],
    realm_id: &str,
) -> Result<String, String> {
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
    let actor_bounds = crate::routing::events::frontier::typed_actor_upper_bounds(actor_frontier)?;
    crate::routing::events::frontier::frontier_root(&realm_frontier, &actor_bounds)
        .map(|root| root.to_string())
}

fn validate_frontier_response(
    state: &arkret_models_collaboration::event_sync::EventsFrontierFederationPeerState,
    peer_id: &str,
    realm_id: &str,
    now: chrono::DateTime<chrono::Utc>,
    document: &arkret_models_identity::DidDocument,
) -> Result<String, String> {
    if state.realm_id.as_str() != realm_id {
        return Err("realm_id_mismatch".to_owned());
    }
    if state.issuer_id.as_str() != peer_id {
        return Err("issuer_mismatch".to_owned());
    }
    let heads = BTreeMap::from([(state.realm_id.clone(), state.head_ids.clone())]);
    let computed =
        crate::routing::events::frontier::frontier_root(&heads, &state.actor_seq_upper_bounds)?;
    if computed != state.frontier_root {
        return Err("frontier_root_mismatch".to_owned());
    }
    let bytes = state
        .signature_binding_bytes(now)
        .map_err(|error| error.to_string())?;
    if arkret_wire::project_did_to_core_id(&document.id).map_err(|error| error.to_string())?
        != state.issuer_id
    {
        return Err("frontier_document_issuer_mismatch".to_owned());
    }
    let method = arkret_wire::DidUrl::new(
        state.signature["verification_method"]
            .as_str()
            .ok_or_else(|| "frontier_verification_method_missing".to_owned())?
            .to_owned(),
    )
    .map_err(|error| error.to_string())?;
    let jws = state.signature["jws"]
        .as_str()
        .ok_or_else(|| "frontier_jws_missing".to_owned())?;
    arkret_identity::verify_jws_with_document_relationship(
        &bytes,
        jws,
        &method,
        &document.id,
        document,
        arkret_identity::DidVerificationRelationship::AssertionMethod,
    )
    .map_err(|error| format!("frontier_signature_invalid:{error}"))?;
    // This worker compares only the issuer's frontier. Optional witness receipts
    // are not consumed or counted as independent witness/quorum evidence here.
    Ok(state.frontier_root.to_string())
}

pub async fn inbound_peer_is_stale(
    state: &AppState,
    realm_id: &str,
    peer_id: &str,
) -> Result<bool, String> {
    let peer_id = arkret_wire::DidCoreId::new(peer_id.to_owned())
        .map_err(|error| format!("invalid_peer_id:{error}"))?;
    state
        .federation()
        .frontier_exchange(realm_id, &peer_id)
        .await
        .map(|record| {
            record.is_some_and(|record| record.status == FEDERATION_FRONTIER_STATUS_PEER_STALE)
        })
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frontier_state_reaches_the_inbound_gate_and_recovers_only_from_ordinary_failure() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let peer = arkret_wire::DidCoreId::new("ak:did_core:web:peer.example").unwrap();
        let realm = "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K";
        for attempt in 1..=3 {
            state
                .federation()
                .record_frontier_failure(realm, &peer, "network_error", attempt)
                .await
                .unwrap();
            assert_eq!(
                inbound_peer_is_stale(&state, realm, peer.as_str())
                    .await
                    .unwrap(),
                attempt == 3
            );
        }
        state
            .federation()
            .record_frontier_success(realm, &peer, "remote-scope-root", 4)
            .await
            .unwrap();
        assert!(
            !inbound_peer_is_stale(&state, realm, peer.as_str())
                .await
                .unwrap()
        );
        state
            .federation()
            .record_frontier_failure(realm, &peer, "fork_quarantine", 5)
            .await
            .unwrap();
        assert!(
            inbound_peer_is_stale(&state, realm, peer.as_str())
                .await
                .unwrap()
        );
        state
            .federation()
            .record_frontier_success(realm, &peer, "equal-root", 6)
            .await
            .unwrap();
        assert!(
            inbound_peer_is_stale(&state, realm, peer.as_str())
                .await
                .unwrap()
        );
    }

    #[test]
    fn frontier_response_validation_requires_bound_peer_and_realm() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let method = arkret_wire::DidUrl::new("did:web:peer.example#service-key").unwrap();
        let now = chrono::DateTime::parse_from_rfc3339("2026-08-31T00:00:00.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let document: arkret_models_identity::DidDocument = serde_json::from_value(serde_json::json!({
            "id": "did:web:peer.example",
            "verificationMethod": [{
                "id": method, "controller": "did:web:peer.example", "type": "Multikey",
                "publicKeyMultibase": arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes())
            }],
            "assertionMethod": [method]
        })).unwrap();
        let mut state: arkret_models_collaboration::event_sync::EventsFrontierFederationPeerState =
            serde_json::from_value(serde_json::json!({
                "realm_id": "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K",
                "head_ids": [], "issuer_id": "ak:did_core:web:peer.example",
                "frontier_root": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "observed_at": "2026-08-31T00:00:00.000Z", "signature": {}
            })).unwrap();
        state.signature =
            crate::routing::events::frontier::sign_frontier_root(&state, &method, &key).unwrap();
        let validate = |candidate: &arkret_models_collaboration::event_sync::EventsFrontierFederationPeerState| {
            validate_frontier_response(candidate, state.issuer_id.as_str(), state.realm_id.as_str(), now, &document)
        };
        assert!(validate(&state).is_ok());
        assert!(state.signature["signed_payload"]["max_hlc"].is_null());
        assert!(state.signature["signed_payload"]["auth_state_root"].is_null());
        assert_eq!(
            validate_frontier_response(
                &state,
                "ak:did_core:web:other.example",
                state.realm_id.as_str(),
                now,
                &document
            )
            .unwrap_err(),
            "issuer_mismatch"
        );

        let mut tampered = state.clone();
        tampered.head_ids.push(arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x42; 32],
        ));
        assert_eq!(validate(&tampered).unwrap_err(), "frontier_root_mismatch");
        let heads = BTreeMap::from([(tampered.realm_id.clone(), tampered.head_ids.clone())]);
        tampered.frontier_root = crate::routing::events::frontier::frontier_root(
            &heads,
            &tampered.actor_seq_upper_bounds,
        )
        .unwrap();
        tampered.signature.insert(
            "signed_payload".to_owned(),
            tampered.signature_payload().unwrap(),
        );
        let bytes =
            arkret_canonical::canonical_json_bytes(&tampered.signature["signed_payload"]).unwrap();
        tampered.signature.insert(
            "payload_digest".to_owned(),
            arkret_canonical::sha256_digest(bytes).into(),
        );
        assert!(
            validate(&tampered)
                .unwrap_err()
                .contains("frontier_signature_invalid")
        );

        let mut tampered = state.clone();
        tampered.max_hlc = Some("01970e589d21-0004-a13f9c2e".to_owned());
        assert!(validate(&tampered).is_err());
        let mut tampered = state.clone();
        tampered.signature = BTreeMap::from([("value".to_owned(), "c2ln".into())]);
        assert!(validate(&tampered).is_err());
        assert!(
            validate_frontier_response(
                &state,
                state.issuer_id.as_str(),
                state.realm_id.as_str(),
                now + chrono::Duration::seconds(301),
                &document
            )
            .is_err()
        );

        let mut rotated = document.clone();
        rotated
            .raw_properties
            .insert("assertionMethod".to_owned(), serde_json::json!([]));
        assert!(
            validate_frontier_response(
                &state,
                state.issuer_id.as_str(),
                state.realm_id.as_str(),
                now,
                &rotated
            )
            .is_err()
        );
        let mut removed_key = document.clone();
        removed_key.verification_methods.clear();
        assert!(
            validate_frontier_response(
                &state,
                state.issuer_id.as_str(),
                state.realm_id.as_str(),
                now,
                &removed_key
            )
            .is_err()
        );

        let mut receipts = state.clone();
        receipts
            .witness_receipts
            .push(BTreeMap::from([("unverified".to_owned(), true.into())]));
        assert_eq!(validate(&receipts).unwrap(), validate(&state).unwrap());
    }

    #[test]
    fn destination_headers_use_verified_route_trust_domain_verbatim() {
        let mut headers = HeaderMap::new();
        insert_destination_binding(
            &mut headers,
            "ak:did_core:webvh:z6mkpeer",
            "ak:trust_domain:verified.example",
        );
        assert_eq!(
            header_value(&headers, "destination-service-id").as_deref(),
            Some("ak:did_core:webvh:z6mkpeer")
        );
        assert_eq!(
            header_value(&headers, "destination-trust-domain").as_deref(),
            Some("ak:trust_domain:verified.example")
        );
    }
}
