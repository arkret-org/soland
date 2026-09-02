use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use arkret_models_collaboration::event_sync::EventsFrontierFederationPeerState;
use arkret_models_collaboration::events_payloads::ForkResolutionSubject;
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue};
use soland_services::events::AcceptedEvent;
use soland_services::federation::FEDERATION_FRONTIER_STATUS_PEER_STALE;

use super::frontier_reduction::{self, ReductionPlan};
use crate::state::AppState;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
// Leave bounded headroom for resolve responses and dependency closure. A
// completed chunk is admitted before its cursor becomes durable.
const CHECKPOINT_SCAN_PAGES: usize = 4;

pub fn spawn(state: AppState) -> Option<Arc<tokio::task::JoinHandle<()>>> {
    if !state.config().federation_outbound_enabled
        || state.config().federation_frontier_interval_seconds == 0
    {
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
        let peers = super::configured_peer_targets(&self.state);
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
            // The one way out is the second phase: an authorized resolution has
            // normalized the scope locally and this peer proves, in its own
            // exact scope, that it now holds the verdict.
            if let Err(error) = self.align_confirmed_evidence(peer_id, realm_id).await {
                tracing::debug!(realm_id, peer_id = %peer_id, reason = %error, "frontier evidence alignment deferred");
            }
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
                    if let Err(error) = self
                        .state
                        .federation()
                        .clear_frontier_reduction_checkpoint(realm_id, peer_id)
                        .await
                    {
                        tracing::warn!(realm_id, peer_id = %peer_id, %error, "frontier checkpoint cleanup deferred");
                        return Ok(None);
                    }
                    return Ok(Some(remote.frontier_root.to_string()));
                }
                ReductionPlan::Challenge(actors) => {
                    let admitted = match self.challenge(peer_id, &remote, &actors).await {
                        Ok(admitted) => admitted,
                        Err(error) if frontier_reduction_deferred(&error) => {
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
        let route = super::resolved_peer_route(&self.state, peer_id.as_str(), "station", false)
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
            PeerEventsQueryOutcome, PeerEventsResolveOutcome, PeerEventsResolveRequestBody,
        };
        let remote_snapshot_digest = arkret_canonical::canonical_sha256(remote)
            .map_err(|error| format!("schema_violation:{error}"))?;
        let actor_set_digest = arkret_canonical::canonical_sha256(&actors)
            .map_err(|error| format!("schema_violation:{error}"))?;
        let stored_checkpoint = self
            .state
            .federation()
            .frontier_reduction_checkpoint(remote.realm_id.as_str(), peer_id)
            .await
            .map_err(|error| format!("temporarily_unavailable:checkpoint_store:{error}"))?;
        let checkpoint_matches = stored_checkpoint.as_ref().is_some_and(|checkpoint| {
            reduction_checkpoint_matches(
                checkpoint,
                &remote_snapshot_digest,
                &actor_set_digest,
                actors,
            )
        });
        if stored_checkpoint.is_some() && !checkpoint_matches {
            self.state
                .federation()
                .clear_frontier_reduction_checkpoint(remote.realm_id.as_str(), peer_id)
                .await
                .map_err(|error| format!("temporarily_unavailable:checkpoint_store:{error}"))?;
        }
        let checkpoint = stored_checkpoint.filter(|_| checkpoint_matches);
        let mut start_actor = checkpoint
            .as_ref()
            .and_then(|checkpoint| {
                actors
                    .iter()
                    .position(|actor| actor == &checkpoint.actor_id)
            })
            .unwrap_or(0);
        let checkpoint_cursor = checkpoint.as_ref().and_then(|checkpoint| {
            checkpoint
                .cursor
                .as_ref()
                .map(|cursor| arkret_wire::Cursor::new(cursor.clone()))
        });
        let checkpoint_cursor = match checkpoint_cursor {
            Some(Ok(cursor)) => Some(cursor),
            Some(Err(_)) => {
                self.state
                    .federation()
                    .clear_frontier_reduction_checkpoint(remote.realm_id.as_str(), peer_id)
                    .await
                    .map_err(|error| format!("temporarily_unavailable:checkpoint_store:{error}"))?;
                start_actor = 0;
                None
            }
            None => None,
        };
        let actor_set = actors.iter().cloned().collect::<BTreeSet<_>>();
        let mut pending: Vec<arkret_wire::EventFederationSubmission> = Vec::new();
        let mut selectors = BTreeSet::new();
        let mut disclosed_positions = BTreeSet::new();
        let mut bytes = 0;
        let mut pages = 0;
        let mut trust_domain = String::new();
        let mut completed_scan_actors = BTreeSet::new();
        let mut next_checkpoint: Option<(arkret_wire::ActorId, Option<String>)> = None;
        'actor_scan: for (actor_index, actor) in actors.iter().enumerate().skip(start_actor) {
            let mut cursor = if actor_index == start_actor {
                checkpoint_cursor.clone()
            } else {
                None
            };
            let mut cursors = BTreeSet::new();
            loop {
                if pages >= CHECKPOINT_SCAN_PAGES {
                    next_checkpoint =
                        Some((actor.clone(), cursor.as_ref().map(ToString::to_string)));
                    break 'actor_scan;
                }
                pages += 1;
                let request = EventsQueryPostRequestBody {
                    realm_ids: vec![remote.realm_id.clone()],
                    actor_ids: vec![actor.clone()],
                    after: cursor.clone(),
                    order: Some("ascending".to_owned()),
                    limit: Some(256),
                    ..Default::default()
                };
                let (page, domain, size): (PeerEventsQueryOutcome, _, _) = self
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
                    crate::routing::events::event_log::verify_frontier_backfill_event(
                        &self.state,
                        &event,
                    )
                    .await?;
                    disclosed_positions.insert((event.actor_id.clone(), event.actor_seq));
                    selectors.insert(event.event_id);
                }
                if !page.has_more {
                    completed_scan_actors.insert(actor.clone());
                    if pages >= CHECKPOINT_SCAN_PAGES && actor_index + 1 < actors.len() {
                        next_checkpoint = Some((actors[actor_index + 1].clone(), None));
                        break 'actor_scan;
                    }
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
        // Advertised heads are resolved only after the bounded actor scan has
        // reached its terminal chunk. Pulling a far-future head into every
        // early chunk would recreate the entire predecessor chain and defeat
        // monotonic checkpoint progress.
        if next_checkpoint.is_none() {
            selectors.extend(remote.head_ids.iter().cloned());
        }
        // Resolve advertised heads, then verified predecessor dependencies.
        // A finite selector and byte budget bounds even adversarial DAGs.
        let mut dependencies = BTreeSet::new();
        let mut resolved = BTreeSet::new();
        let mut admitted = BTreeSet::new();
        let mut dependency_closure_complete = false;
        for _ in 0..64 {
            for submission in &pending {
                let event = &submission.event;
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
                    directory_source_ref_access: None,
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
                for submission in &outcome.events {
                    let event = &submission.event;
                    let digest_suite = arkret::signed_event_digest_claim(event)
                        .and_then(|digest| digest.digest_suite().map_err(Into::into))
                        .map_err(|error| format!("schema_violation:{error}"))?;
                    submission
                        .validate_structural(digest_suite)
                        .map_err(|error| format!("schema_violation:{error}"))?;
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
                    .any(|submission| submission.event.realm_id != remote.realm_id)
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
        for actor in &completed_scan_actors {
            let upper = remote.actor_seq_upper_bounds[actor];
            if !disclosed_positions.contains(&(actor.clone(), upper)) {
                return Err("schema_violation:advertised_actor_bound_not_disclosed".to_owned());
            }
        }
        pending.retain(|submission| {
            let event = &submission.event;
            actor_set.contains(&event.actor_id) || dependencies.contains(&event.event_id)
        });
        pending.sort_by(|a, b| {
            (a.event.actor_seq, &a.event.event_id).cmp(&(b.event.actor_seq, &b.event.event_id))
        });
        let mut seal_selectors = BTreeSet::new();
        for submission in &pending {
            if let Some(seal_ref) = &submission.event.seal_ref {
                seal_selectors.insert(seal_ref.clone());
            }
            if let Some(seal_basis) = &submission.event.seal_basis {
                seal_selectors.extend(seal_basis.leaves.iter().cloned());
            }
        }
        let mut missing_seal_selectors = BTreeSet::new();
        for seal_ref in seal_selectors {
            if self
                .state
                .projections()
                .seal_by_id(&seal_ref)
                .map_err(|error| error.to_string())?
                .is_none()
            {
                missing_seal_selectors.insert(seal_ref);
            }
        }
        let mut seal_selectors = missing_seal_selectors;
        let mut resolved_seals = BTreeMap::new();
        while !seal_selectors.is_empty() {
            let batch = seal_selectors.iter().take(256).cloned().collect::<Vec<_>>();
            let request = arkret_models_collaboration::http_bodies::PeerSealResolveRequestBody {
                realm_id: remote.realm_id.clone(),
                seal_refs: batch.clone(),
                history_traversal_access: None,
            };
            let (outcome, domain, size): (
                arkret_models_collaboration::http_bodies::SealResolveOutcome,
                _,
                _,
            ) = self
                .peer_query(peer_id, "/_arkret/peer/seals/resolve", &request)
                .await?;
            trust_domain = domain;
            bytes += size;
            pages += 1;
            if pages > 128 || bytes > 64 * 1024 * 1024 {
                return Err("temporarily_unavailable:dependency_budget".to_owned());
            }
            outcome
                .validate_for_peer_request(&request)
                .map_err(|error| format!("schema_violation:{error}"))?;
            if !outcome.missing_seal_refs.is_empty() {
                return Err("dependency_missing:seal_prerequisite".to_owned());
            }
            for seal_ref in batch {
                seal_selectors.remove(&seal_ref);
            }
            for seal in outcome.seals {
                if seal.realm_id != remote.realm_id {
                    return Err("schema_violation:seal_dependency_realm_mismatch".to_owned());
                }
                for predecessor in &seal.predecessor_refs {
                    let is_local = self
                        .state
                        .projections()
                        .seal_by_id(predecessor)
                        .map_err(|error| error.to_string())?
                        .is_some();
                    if !is_local && !resolved_seals.contains_key(predecessor) {
                        seal_selectors.insert(predecessor.clone());
                    }
                }
                resolved_seals.insert(seal.id.clone(), seal);
            }
        }
        let resolved_seals = resolved_seals.into_values().collect::<Vec<_>>();
        let mut admission_complete = false;
        for _ in 0..64 {
            if pending.is_empty() {
                admission_complete = true;
                break;
            }
            let mut retry = Vec::new();
            let mut progress = false;
            for submission in pending {
                let existing = self
                    .state
                    .event_queries()
                    .canonical_event(submission.event.event_id.as_str())
                    .await
                    .map_err(|error| error.to_string())?;
                match crate::routing::events::event_log::admit_frontier_backfill_event(
                    &self.state,
                    peer_id.as_str(),
                    &trust_domain,
                    &submission,
                    &resolved_seals,
                )
                .await
                {
                    Ok(_) => {
                        admitted.insert(submission.event.event_id.to_string());
                        progress = true;
                    }
                    Err(error) if error.code == "dependency_missing" => retry.push(submission),
                    Err(error) => {
                        if error.quarantine_event_id.is_some() {
                            let subject = self
                                .confirmed_evidence_subject(
                                    &submission.event,
                                    existing.as_ref(),
                                    &error.code,
                                )
                                .await?;
                            self.record_confirmed_evidence(
                                peer_id,
                                remote.realm_id.as_str(),
                                &error.code,
                                subject,
                            )
                            .await?;
                            return Err("confirmed_evidence_recorded".to_owned());
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
        if !admission_complete {
            return Err("temporarily_unavailable:admission_round_budget".to_owned());
        }
        if let Some((actor_id, cursor)) = next_checkpoint {
            self.state
                .federation()
                .put_frontier_reduction_checkpoint(
                    &soland_services::federation::FederationFrontierReductionCheckpoint {
                        realm_id: remote.realm_id.to_string(),
                        peer_id: peer_id.clone(),
                        remote_snapshot_digest,
                        actor_set_digest,
                        actor_id,
                        cursor,
                        updated_at: chrono::Utc::now().timestamp(),
                    },
                )
                .await
                .map_err(|error| format!("temporarily_unavailable:checkpoint_store:{error}"))?;
            return Err("temporarily_unavailable:challenge_page_budget".to_owned());
        }
        self.state
            .federation()
            .clear_frontier_reduction_checkpoint(remote.realm_id.as_str(), peer_id)
            .await
            .map_err(|error| format!("temporarily_unavailable:checkpoint_store:{error}"))?;
        Ok(admitted)
    }

    /// Second phase of clearing confirmed fork evidence.
    ///
    /// An accepted `ak.fork.resolution` normalizes local state only. Before a
    /// peer leaves `peer_stale`, that peer has to prove through its own
    /// authenticated exact-scope challenge that its canonical sibling set now
    /// equals the verdict — exactly the winner, or empty for `void_all`
    /// (`sync/federation.md` section 4.5.3). Global root equality, an ordinary
    /// successful exchange, and another peer having aligned are all
    /// insufficient, so none of them reach this path.
    ///
    /// Only the exact evidence key that aligned is cleared. Other unresolved
    /// evidence for the same peer and the ordinary failure window are
    /// untouched.
    async fn align_confirmed_evidence(
        &self,
        peer_id: &arkret_wire::DidCoreId,
        realm_id: &str,
    ) -> Result<(), String> {
        let unresolved = self
            .state
            .federation()
            .unresolved_frontier_confirmed_evidence(realm_id, peer_id)
            .await
            .map_err(|error| format!("temporarily_unavailable:evidence_store:{error}"))?;
        for evidence in unresolved {
            let Some(normalization) = self
                .state
                .federation()
                .frontier_local_normalization(realm_id, &evidence.evidence_scope_key)
                .await
                .map_err(|error| format!("temporarily_unavailable:resolution_store:{error}"))?
            else {
                // No authorized resolution for this scope yet. Staying fail
                // closed is the correct outcome, not an error.
                continue;
            };
            let subject: ForkResolutionSubject =
                serde_json::from_value(normalization.subject.clone())
                    .map_err(|error| format!("schema_violation:{error}"))?;
            let verdict: arkret_models_collaboration::events_payloads::ForkResolutionVerdict =
                serde_json::from_value(normalization.verdict.clone())
                    .map_err(|error| format!("schema_violation:{error}"))?;
            if !self
                .peer_scope_matches_verdict(peer_id, realm_id, &subject, &verdict)
                .await?
            {
                continue;
            }
            self.state
                .federation()
                .resolve_frontier_confirmed_evidence_for_peer(
                    realm_id,
                    peer_id,
                    &evidence.evidence_scope_key,
                    "fork_resolution_event",
                    &normalization.resolution_event_digest,
                    chrono::Utc::now().timestamp(),
                )
                .await
                .map_err(|error| format!("temporarily_unavailable:evidence_store:{error}"))?;
        }
        Ok(())
    }

    /// Ask this peer for the disputed scope and decide whether what it returns
    /// is byte-for-byte the verdict.
    async fn peer_scope_matches_verdict(
        &self,
        peer_id: &arkret_wire::DidCoreId,
        realm_id: &str,
        subject: &ForkResolutionSubject,
        verdict: &arkret_models_collaboration::events_payloads::ForkResolutionVerdict,
    ) -> Result<bool, String> {
        use arkret_models_collaboration::events_payloads::ForkResolutionVerdict;
        match subject {
            ForkResolutionSubject::EventSiblingPosition {
                actor_id,
                actor_seq,
            } => {
                let siblings = self
                    .peer_sibling_events(peer_id, realm_id, actor_id, *actor_seq)
                    .await?;
                let observed = siblings
                    .iter()
                    .map(|event| event.event_id.clone())
                    .collect::<BTreeSet<_>>();
                Ok(match verdict {
                    ForkResolutionVerdict::SiblingWinner {
                        winner_event_id, ..
                    } => observed == BTreeSet::from([winner_event_id.clone()]),
                    ForkResolutionVerdict::VoidAll { .. } => observed.is_empty(),
                    // A collision verdict cannot govern a sibling position; the
                    // Move that produced this pairing would not have been
                    // admitted, so treat it as unaligned rather than guess.
                    ForkResolutionVerdict::CollisionWinner { .. } => false,
                })
            }
            ForkResolutionSubject::EventIdCollision { event_id } => {
                let held = self.peer_variant_bytes(peer_id, realm_id, event_id).await?;
                Ok(match verdict {
                    ForkResolutionVerdict::VoidAll { .. } => held.is_none(),
                    ForkResolutionVerdict::CollisionWinner {
                        winner_preimage, ..
                    } => {
                        // Two variants share one identity, so alignment is only
                        // provable on the complete canonical bytes.
                        let Some(held) = held else {
                            return Ok(false);
                        };
                        held == self
                            .local_winner_canonical_bytes(realm_id, winner_preimage)
                            .await?
                    }
                    ForkResolutionVerdict::SiblingWinner { .. } => false,
                })
            }
        }
    }

    /// Every Event this peer discloses at one exact `(actor_id, actor_seq)`.
    ///
    /// Discovery only, and every row is fully re-verified: a peer claiming to
    /// have aligned must show Events that stand on their own.
    async fn peer_sibling_events(
        &self,
        peer_id: &arkret_wire::DidCoreId,
        realm_id: &str,
        actor_id: &arkret_wire::ActorId,
        actor_seq: u64,
    ) -> Result<Vec<arkret_wire::Event>, String> {
        use arkret_models_collaboration::event_query::EventsQueryPostRequestBody;
        use arkret_models_collaboration::http_bodies::PeerEventsQueryOutcome;
        let realm = arkret_identifiers::RealmId::new(realm_id.to_owned())
            .map_err(|error| format!("invalid_realm_id:{error}"))?;
        let mut cursor: Option<arkret_wire::Cursor> = None;
        let mut cursors = BTreeSet::new();
        let mut siblings = Vec::new();
        for _ in 0..CHECKPOINT_SCAN_PAGES {
            let request = EventsQueryPostRequestBody {
                realm_ids: vec![realm.clone()],
                actor_ids: vec![actor_id.clone()],
                after: cursor.clone(),
                order: Some("ascending".to_owned()),
                limit: Some(256),
                ..Default::default()
            };
            let (page, _, _): (PeerEventsQueryOutcome, _, _) = self
                .peer_query(peer_id, "/_arkret/peer/events", &request)
                .await?;
            let has_more = page.has_more;
            let next_cursor = page.next_cursor.clone();
            for row in page.events {
                let event = row
                    .into_event()
                    .ok_or_else(|| "schema_violation:alignment_requires_full_event".to_owned())?;
                if event.realm_id != realm || &event.actor_id != actor_id {
                    return Err("schema_violation:alignment_selector_mismatch".to_owned());
                }
                if event.actor_seq != actor_seq {
                    continue;
                }
                crate::routing::events::event_log::verify_frontier_backfill_event(
                    &self.state,
                    &event,
                )
                .await?;
                siblings.push(event);
            }
            if !has_more {
                return Ok(siblings);
            }
            let next =
                next_cursor.ok_or_else(|| "schema_violation:missing_scan_cursor".to_owned())?;
            if !cursors.insert(next.clone()) {
                return Err("schema_violation:repeated_scan_cursor".to_owned());
            }
            cursor = Some(arkret_wire::Cursor::new(next).map_err(|error| error.to_string())?);
        }
        // The peer did not finish disclosing this position inside the pass
        // budget. That is not alignment, and it is not a peer failure either.
        Err("temporarily_unavailable:alignment_page_budget".to_owned())
    }

    /// The canonical preimage bytes this peer holds for one colliding identity,
    /// or `None` when it holds no variant at all.
    async fn peer_variant_bytes(
        &self,
        peer_id: &arkret_wire::DidCoreId,
        realm_id: &str,
        event_id: &arkret_wire::EventId,
    ) -> Result<Option<Vec<u8>>, String> {
        use arkret_models_collaboration::http_bodies::{
            PeerEventsResolveOutcome, PeerEventsResolveRequestBody,
        };
        let request = PeerEventsResolveRequestBody {
            realm_id: arkret_identifiers::RealmId::new(realm_id.to_owned())
                .map_err(|error| format!("invalid_realm_id:{error}"))?,
            event_ids: vec![event_id.clone()],
            event_digests: Vec::new(),
            include_payload: Some(true),
            max_response_bytes: Some(8 * 1024 * 1024),
            history_traversal_access: None,
            directory_source_ref_access: None,
        };
        let (outcome, _, _): (PeerEventsResolveOutcome, _, _) = self
            .peer_query(peer_id, "/_arkret/peer/events/resolve", &request)
            .await?;
        let Some(submission) = outcome.events.into_iter().next() else {
            return Ok(None);
        };
        let digest_suite = arkret::signed_event_digest_claim(&submission.event)
            .and_then(|digest| digest.digest_suite().map_err(Into::into))
            .map_err(|error| format!("schema_violation:{error}"))?;
        submission
            .validate_structural(digest_suite)
            .map_err(|error| format!("schema_violation:{error}"))?;
        let event = submission.event;
        if event.event_id != *event_id || event.realm_id.as_str() != realm_id {
            return Err("schema_violation:alignment_selector_mismatch".to_owned());
        }
        crate::routing::events::event_log::verify_frontier_backfill_event(&self.state, &event)
            .await?;
        Ok(Some(
            arkret_canonical::canonical_json_bytes(
                &event
                    .digest_payload()
                    .map_err(|error| format!("schema_violation:{error}"))?,
            )
            .map_err(|error| format!("schema_violation:{error}"))?,
        ))
    }

    /// Canonical bytes of the winner the local verdict names.
    ///
    /// The resolution Move is already accepted here, so its inline bytes and
    /// the governance-dependency record it may reference are both local reads.
    async fn local_winner_canonical_bytes(
        &self,
        realm_id: &str,
        winner: &arkret_models_collaboration::events_payloads::ForkResolutionVariantLocator,
    ) -> Result<Vec<u8>, String> {
        use arkret_models_collaboration::events_payloads::ForkResolutionVariantLocator;
        use arkret_models_collaboration::governance_dependencies::{
            GovernanceDependency, GovernanceDependencySelector,
        };
        match winner {
            ForkResolutionVariantLocator::InlineCanonicalBytes {
                canonical_event_bytes_b64u,
            } => arkret_canonical::base64url_decode(canonical_event_bytes_b64u.as_str())
                .map_err(|error| format!("schema_violation:{error}")),
            ForkResolutionVariantLocator::CollisionVariantRecord {
                collision_variant_record_digest,
                ..
            } => {
                let realm = arkret_identifiers::RealmId::new(realm_id.to_owned())
                    .map_err(|error| format!("invalid_realm_id:{error}"))?;
                let selector = GovernanceDependencySelector::CollisionVariantRecord {
                    content_digest: collision_variant_record_digest.clone(),
                };
                let dependency = self
                    .state
                    .persistence()
                    .governance_dependency_store()
                    .get(&realm, &selector)
                    .await
                    .map_err(|error| format!("temporarily_unavailable:record_store:{error}"))?
                    .ok_or_else(|| "dependency_missing:collision_variant_record".to_owned())?;
                let GovernanceDependency::CollisionVariantRecord {
                    collision_variant_record,
                    ..
                } = dependency
                else {
                    return Err("schema_violation:collision_variant_record_kind".to_owned());
                };
                collision_variant_record
                    .canonical_event_bytes()
                    .map_err(|error| format!("schema_violation:{error}"))
            }
        }
    }

    async fn confirmed_evidence_subject(
        &self,
        event: &arkret_wire::Event,
        existing: Option<&AcceptedEvent>,
        reason: &str,
    ) -> Result<ForkResolutionSubject, String> {
        // The subject is the disputed scope alone. It is deliberately not the
        // evidence: a later `ak.fork.resolution` clears this row by matching
        // the same cell subject, and single-bucket versus cross-bucket
        // over-fork at one position must resolve into one row rather than two
        // that could be cleared independently.
        match reason {
            "witness_disagreement" => {
                // A collision needs both preimages to have actually been seen
                // locally; a single variant is a mismatch report, not evidence.
                let existing = existing.ok_or_else(|| {
                    "schema_violation:collision_evidence_missing_original_variant".to_owned()
                })?;
                let incoming = arkret_canonical::canonical_json_bytes(
                    &event.digest_payload().map_err(|error| error.to_string())?,
                )
                .map_err(|error| format!("schema_violation:{error}"))?;
                if existing.canonical_bytes == incoming {
                    return Err(
                        "schema_violation:collision_evidence_variants_not_distinct".to_owned()
                    );
                }
                Ok(ForkResolutionSubject::EventIdCollision {
                    event_id: event.event_id.clone(),
                })
            }
            "fork_quarantine" => Ok(ForkResolutionSubject::EventSiblingPosition {
                actor_id: event.actor_id.clone(),
                actor_seq: event.actor_seq,
            }),
            _ => Err(format!(
                "schema_violation:unregistered_confirmed_evidence_reason:{reason}"
            )),
        }
    }

    async fn record_confirmed_evidence(
        &self,
        peer_id: &arkret_wire::DidCoreId,
        realm_id: &str,
        reason: &str,
        subject: ForkResolutionSubject,
    ) -> Result<(), String> {
        let evidence_scope_key = subject
            .cell_subject_key()
            .map_err(|error| format!("schema_violation:{error}"))?;
        let evidence_scope =
            serde_json::to_value(subject).map_err(|error| format!("schema_violation:{error}"))?;
        self.state
            .federation()
            .record_frontier_confirmed_evidence(
                &soland_services::federation::FederationFrontierConfirmedEvidenceRecord {
                    realm_id: realm_id.to_owned(),
                    peer_id: peer_id.clone(),
                    evidence_scope_key: evidence_scope_key.to_string(),
                    reason: reason.to_owned(),
                    evidence_scope,
                    observed_at: chrono::Utc::now().timestamp(),
                    resolution_kind: None,
                    resolution_digest: None,
                    resolved_at: None,
                },
            )
            .await
            .map_err(|error| error.to_string())
    }

    async fn probe_peer(
        &self,
        peer_id: &arkret_wire::DidCoreId,
        realm_id: &str,
    ) -> Result<EventsFrontierFederationPeerState, String> {
        let route = super::resolved_peer_route(&self.state, peer_id.as_str(), "station", false)
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
            super::resolved_peer_route(&self.state, peer_id.as_str(), "station", true).await?;
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

fn frontier_reduction_deferred(reason: &str) -> bool {
    matches!(
        reason,
        "temporarily_unavailable:challenge_page_budget"
            | "temporarily_unavailable:challenge_byte_budget"
            | "temporarily_unavailable:dependency_budget"
            | "temporarily_unavailable:admission_round_budget"
            | "temporarily_unavailable:backfill_publication_evidence_unavailable"
            | "confirmed_evidence_recorded"
    ) || reason.starts_with("temporarily_unavailable:checkpoint_store:")
}

fn reduction_checkpoint_matches(
    checkpoint: &soland_services::federation::FederationFrontierReductionCheckpoint,
    remote_snapshot_digest: &str,
    actor_set_digest: &str,
    actors: &[arkret_wire::ActorId],
) -> bool {
    checkpoint.remote_snapshot_digest == remote_snapshot_digest
        && checkpoint.actor_set_digest == actor_set_digest
        && actors.contains(&checkpoint.actor_id)
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

    #[test]
    fn reduction_checkpoint_is_bound_to_snapshot_actor_set_and_complete_actor() {
        let principal = arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            principal.clone(),
            arkret_wire::DidCoreId::new("ak:did_core:web:station-a.example").unwrap(),
        ));
        let other_station_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            principal,
            arkret_wire::DidCoreId::new("ak:did_core:web:station-b.example").unwrap(),
        ));
        let checkpoint = soland_services::federation::FederationFrontierReductionCheckpoint {
            realm_id: "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K".to_owned(),
            peer_id: arkret_wire::DidCoreId::new("ak:did_core:web:peer.example").unwrap(),
            remote_snapshot_digest: "sha256:snapshot-a".to_owned(),
            actor_set_digest: "sha256:actors-a".to_owned(),
            actor_id: actor.clone(),
            cursor: Some("cursor".to_owned()),
            updated_at: 1,
        };
        assert!(reduction_checkpoint_matches(
            &checkpoint,
            "sha256:snapshot-a",
            "sha256:actors-a",
            std::slice::from_ref(&actor)
        ));
        assert!(!reduction_checkpoint_matches(
            &checkpoint,
            "sha256:snapshot-b",
            "sha256:actors-a",
            std::slice::from_ref(&actor)
        ));
        assert!(!reduction_checkpoint_matches(
            &checkpoint,
            "sha256:snapshot-a",
            "sha256:actors-b",
            std::slice::from_ref(&actor)
        ));
        assert!(!reduction_checkpoint_matches(
            &checkpoint,
            "sha256:snapshot-a",
            "sha256:actors-a",
            &[other_station_actor]
        ));
        assert!(frontier_reduction_deferred(
            "temporarily_unavailable:checkpoint_store:database offline"
        ));
        assert!(!frontier_reduction_deferred("network_error:timeout"));
    }

    #[tokio::test]
    async fn frontier_state_reaches_the_inbound_gate_and_recovers_only_from_ordinary_failure() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let peer = arkret_wire::DidCoreId::new("ak:did_core:web:peer.example").unwrap();
        let realm = "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K";
        let checkpoint = soland_services::federation::FederationFrontierReductionCheckpoint {
            realm_id: realm.to_owned(),
            peer_id: peer.clone(),
            remote_snapshot_digest: "sha256:remote-snapshot".to_owned(),
            actor_set_digest: "sha256:actor-set".to_owned(),
            actor_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                arkret_wire::DidCoreId::new("ak:did_core:web:station-a.example").unwrap(),
            )),
            cursor: Some("opaque-cursor".to_owned()),
            updated_at: 0,
        };
        state
            .federation()
            .put_frontier_reduction_checkpoint(&checkpoint)
            .await
            .unwrap();
        assert_eq!(
            state
                .federation()
                .frontier_reduction_checkpoint(realm, &peer)
                .await
                .unwrap(),
            Some(checkpoint)
        );
        state
            .federation()
            .clear_frontier_reduction_checkpoint(realm, &peer)
            .await
            .unwrap();
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
        let subject = ForkResolutionSubject::EventSiblingPosition {
            actor_id: arkret_wire::ActorId::service(peer.clone()),
            actor_seq: 7,
        };
        let scope_key = subject.cell_subject_key().unwrap();
        state
            .federation()
            .record_frontier_confirmed_evidence(
                &soland_services::federation::FederationFrontierConfirmedEvidenceRecord {
                    realm_id: realm.to_owned(),
                    peer_id: peer.clone(),
                    evidence_scope_key: scope_key.to_string(),
                    reason: "fork_quarantine".to_owned(),
                    evidence_scope: serde_json::to_value(&subject).unwrap(),
                    observed_at: 5,
                    resolution_kind: None,
                    resolution_digest: None,
                    resolved_at: None,
                },
            )
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
        assert!(
            !state
                .federation()
                .resolve_frontier_confirmed_evidence_for_peer(
                    realm,
                    &peer,
                    "sha256:wrong-scope",
                    "fork_resolution_event",
                    &format!("sha256:{}", "3".repeat(64)),
                    7,
                )
                .await
                .unwrap()
        );
        assert!(
            inbound_peer_is_stale(&state, realm, peer.as_str())
                .await
                .unwrap()
        );
        // Alignment is proved one peer at a time: a second peer holding the
        // same disputed scope stays fail closed while this one clears.
        let other_peer = arkret_wire::DidCoreId::new("ak:did_core:web:peer-b.example").unwrap();
        state
            .federation()
            .record_frontier_confirmed_evidence(
                &soland_services::federation::FederationFrontierConfirmedEvidenceRecord {
                    realm_id: realm.to_owned(),
                    peer_id: other_peer.clone(),
                    evidence_scope_key: scope_key.to_string(),
                    reason: "fork_quarantine".to_owned(),
                    evidence_scope: serde_json::to_value(&subject).unwrap(),
                    observed_at: 5,
                    resolution_kind: None,
                    resolution_digest: None,
                    resolved_at: None,
                },
            )
            .await
            .unwrap();
        assert!(
            state
                .federation()
                .resolve_frontier_confirmed_evidence_for_peer(
                    realm,
                    &peer,
                    scope_key.as_str(),
                    "fork_resolution_event",
                    &format!("sha256:{}", "3".repeat(64)),
                    8,
                )
                .await
                .unwrap()
        );
        assert!(
            !inbound_peer_is_stale(&state, realm, peer.as_str())
                .await
                .unwrap()
        );
        assert!(
            inbound_peer_is_stale(&state, realm, other_peer.as_str())
                .await
                .unwrap(),
            "another peer aligning must not clear this one"
        );
        assert!(
            !state
                .federation()
                .resolve_frontier_confirmed_evidence_for_peer(
                    realm,
                    &peer,
                    scope_key.as_str(),
                    "fork_resolution_event",
                    &format!("sha256:{}", "3".repeat(64)),
                    9,
                )
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn local_normalization_is_recorded_once_and_clears_no_peer_by_itself() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let realm = "ak:realm:AQOJcuEsMahV_eXZxrvKxOc_1fBMQCLgofI2jenpts5n";
        let peer = arkret_wire::DidCoreId::new("ak:did_core:web:peer-a.example").unwrap();
        let subject = ForkResolutionSubject::EventSiblingPosition {
            actor_id: arkret_wire::ActorId::service(peer.clone()),
            actor_seq: 7,
        };
        let scope_key = subject.cell_subject_key().unwrap();
        state
            .federation()
            .record_frontier_confirmed_evidence(
                &soland_services::federation::FederationFrontierConfirmedEvidenceRecord {
                    realm_id: realm.to_owned(),
                    peer_id: peer.clone(),
                    evidence_scope_key: scope_key.to_string(),
                    reason: "fork_quarantine".to_owned(),
                    evidence_scope: serde_json::to_value(&subject).unwrap(),
                    observed_at: 1,
                    resolution_kind: None,
                    resolution_digest: None,
                    resolved_at: None,
                },
            )
            .await
            .unwrap();

        let normalization = soland_services::federation::FederationFrontierResolutionRecord {
            realm_id: realm.to_owned(),
            cell_subject_key: scope_key.to_string(),
            subject: serde_json::to_value(&subject).unwrap(),
            verdict: serde_json::json!({"kind": "void_all"}),
            conflict_evidence_digest: format!("sha256:{}", "4".repeat(64)),
            resolution_event_digest: format!("sha256:{}", "5".repeat(64)),
            normalized_at: 2,
        };
        state
            .federation()
            .record_frontier_local_normalization(&normalization)
            .await
            .unwrap();
        // Replaying one accepted Event is idempotent.
        state
            .federation()
            .record_frontier_local_normalization(&normalization)
            .await
            .unwrap();
        assert_eq!(
            state
                .federation()
                .frontier_local_normalization(realm, scope_key.as_str())
                .await
                .unwrap()
                .as_ref(),
            Some(&normalization)
        );
        // Local normalization on its own leaves the peer fail closed: nothing
        // yet shows that this peer's sibling set matches the verdict.
        assert!(
            inbound_peer_is_stale(&state, realm, peer.as_str())
                .await
                .unwrap()
        );

        // A second, different verdict for a settled subject is a causal
        // successor that must fail rather than silently re-adjudicate.
        let mut reversed = normalization.clone();
        reversed.verdict = serde_json::json!({
            "kind": "canonical_winner",
            "winner_event_id": "ak:event:AUl7i16DNG_PX5V_-ud5fDx65PwcMpaj4uSW2K4C0Ev9"
        });
        assert!(
            state
                .federation()
                .record_frontier_local_normalization(&reversed)
                .await
                .is_err()
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
