//! Durable acquisition of organization-recovery archive traversal material.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use arkret_models_collaboration::governance_dependencies::{
    GovernanceDependency, GovernanceDependencyResolveOutcome, GovernanceDependencySelector,
    PeerGovernanceDependencyResolveRequest, governance_attester_evidence_selectors,
    governance_runtime_dependency_selector_coordinates_for_acquisition,
};
use arkret_models_collaboration::history_key::{
    HistoryGovernanceTraversalIntent, OrganizationRecoveryArchiveReplica,
    OrganizationRecoveryArchiveReplicaOutcome, PeerHistoryTraversalAccess,
    SelfHistoryTraversalAccess,
};
use arkret_models_collaboration::http_bodies::{
    PeerEventsResolveOutcome, PeerEventsResolveRequestBody, PeerSealResolveRequestBody,
    SealResolveOutcome,
};
use arkret_wire::{Event, EventKind, Hash, Seal, SealId};
use chrono::Utc;
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::Serialize;
use serde::de::DeserializeOwned;
use soland_storage::{
    HistoryTraversalAccess, HistoryTraversalPin, HistoryTraversalRetainedObject,
    HistoryTraversalRetentionWrite, PendingRrkAcquisitionRecord, PendingRrkAcquisitionState,
    StorageCasOutcome,
};
use uuid::Uuid;

use crate::state::AppState;

const PASS_INTERVAL: Duration = Duration::from_secs(10);
const CLAIM_TTL: chrono::Duration = chrono::Duration::minutes(30);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RESPONSE_BYTES: usize = 8 * 1_024 * 1_024;
const MAX_RETAINED_OBJECTS: usize = 4_096;

pub fn spawn(state: AppState) -> Option<Arc<tokio::task::JoinHandle<()>>> {
    if !state.config().federation_outbound_enabled {
        return None;
    }
    Some(RrkAcquisitionWorker::new(state).spawn())
}

pub struct RrkAcquisitionWorker {
    state: AppState,
    worker_id: String,
}

impl RrkAcquisitionWorker {
    pub fn new(state: AppState) -> Self {
        Self {
            worker_id: format!("{}#{}", state.service_id(), Uuid::new_v4()),
            state,
        }
    }

    pub fn spawn(self) -> Arc<tokio::task::JoinHandle<()>> {
        Arc::new(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(PASS_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                if let Err(error) = self.run_one_pass().await {
                    tracing::warn!(
                        %error,
                        worker = "rrk_acquisition",
                        "RRK acquisition pass failed"
                    );
                }
            }
        }))
    }

    pub async fn run_one_pass(&self) -> Result<(), String> {
        let now = Utc::now();
        let claim_token = format!("{}:{}", self.worker_id, Uuid::new_v4());
        let records = self
            .state
            .persistence()
            .governance_history_service()
            .claim_due_rrk(now, &claim_token, now + CLAIM_TTL, 16)
            .await
            .map_err(|error| error.to_string())?;
        for record in records {
            if let Err(error) = self.acquire(&record, &claim_token).await {
                let delay = retry_delay(record.attempt_count);
                let _ = self
                    .state
                    .persistence()
                    .governance_history_service()
                    .retry_rrk(
                        &record.input.acquisition_digest,
                        &claim_token,
                        record.attempt_count,
                        Utc::now() + delay,
                        stable_error_code(&error),
                        Utc::now(),
                    )
                    .await;
                tracing::warn!(
                    acquisition_digest = %record.input.acquisition_digest,
                    source_id = %record.input.archive_replica.source_id,
                    %error,
                    worker = "rrk_acquisition",
                    "RRK traversal acquisition will retry"
                );
            }
        }
        Ok(())
    }

    async fn acquire(
        &self,
        record: &PendingRrkAcquisitionRecord,
        claim_token: &str,
    ) -> Result<(), String> {
        let replica = &record.input.archive_replica;
        if record.state == PendingRrkAcquisitionState::Ready {
            return self.accept_ready(record, claim_token).await;
        }
        let closure = self.fetch_and_verify_closure(replica).await?;
        let write = retained_write(replica, &record.input.archive_replica_digest, closure)?;
        self.state
            .persistence()
            .governance_history_service()
            .persist_history_traversal_retention(write)
            .await
            .map_err(|error| format!("retention_persist:{error}"))?;

        let ready_at = Utc::now();
        match self
            .state
            .persistence()
            .governance_history_service()
            .mark_rrk_ready(
                &record.input.acquisition_digest,
                claim_token,
                record.attempt_count,
                ready_at,
            )
            .await
            .map_err(|error| format!("ready_cas:{error}"))?
        {
            StorageCasOutcome::Applied | StorageCasOutcome::ExactReplay => {}
            StorageCasOutcome::Mismatch => return Err("ready_claim_moved".to_owned()),
        }
        let ready = self
            .state
            .persistence()
            .governance_history_service()
            .rrk_acquisition(&record.input.acquisition_digest)
            .await
            .map_err(|error| format!("ready_read:{error}"))?
            .ok_or_else(|| "ready_record_missing".to_owned())?;
        self.accept_ready(&ready, claim_token).await
    }

    async fn accept_ready(
        &self,
        ready: &PendingRrkAcquisitionRecord,
        claim_token: &str,
    ) -> Result<(), String> {
        let replica = &ready.input.archive_replica;
        let sequence = ready
            .archive_sequence
            .ok_or_else(|| "ready_sequence_missing".to_owned())?;
        let accepted_at = Utc::now();
        let verification_method = self
            .state
            .service_verification_method("notary-key")
            .map_err(|error| format!("local_verification_method:{error}"))?;
        let outcome = OrganizationRecoveryArchiveReplicaOutcome::build_signed_proof(
            verification_method,
            accepted_at,
            |service_proof| OrganizationRecoveryArchiveReplicaOutcome {
                archive_replica_digest: ready.input.archive_replica_digest.clone(),
                holder_id: replica.holder_id.clone(),
                archive_sequence: sequence,
                accepted_at,
                service_proof,
            },
            |binding| {
                arkret_signatures::jws::sign_jws_ed25519(
                    binding,
                    self.state.notary_signing_key().as_ref(),
                )
                .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))
            },
        )
        .map_err(|error| format!("acceptance_sign:{error}"))?;
        match self
            .state
            .persistence()
            .governance_history_service()
            .accept_rrk(
                &ready.input.acquisition_digest,
                claim_token,
                ready.attempt_count,
                outcome,
            )
            .await
            .map_err(|error| format!("accept_cas:{error}"))?
        {
            StorageCasOutcome::Applied | StorageCasOutcome::ExactReplay => Ok(()),
            StorageCasOutcome::Mismatch => Err("accept_claim_moved".to_owned()),
        }
    }

    async fn fetch_and_verify_closure(
        &self,
        replica: &OrganizationRecoveryArchiveReplica,
    ) -> Result<VerifiedClosure, String> {
        let HistoryGovernanceTraversalIntent::OrganizationRecoveryArchive {
            effective_scope,
            trusted_history_base_basis,
            target_basis,
            ..
        } = &replica.history_traversal_retention.traversal_intent
        else {
            return Err("intent_branch_mismatch".to_owned());
        };
        let realm_id = match effective_scope {
            arkret_wire::HistoryEffectiveScope::Realm { realm_id }
            | arkret_wire::HistoryEffectiveScope::Circle { realm_id, .. } => realm_id,
        };
        let base_checkpoint =
            super::super::events::event_log::governance_proof::load_verified_governance_checkpoint(
                &self.state,
                realm_id,
                trusted_history_base_basis,
            )
            .await
            .map_err(|error| format!("base_checkpoint:{error}"))?;
        let access = PeerHistoryTraversalAccess::PendingArchiveReplica {
            pending_archive_replica_digest: replica
                .archive_replica_digest()
                .map_err(|error| format!("replica_digest:{error}"))?,
        };
        let trusted_base_leaves = trusted_history_base_basis
            .leaves
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let mut seals = BTreeMap::<SealId, Seal>::new();
        let mut pending = target_basis
            .leaves
            .iter()
            .filter(|seal_id| !trusted_base_leaves.contains(*seal_id))
            .cloned()
            .collect::<BTreeSet<_>>();
        while !pending.is_empty() {
            if seals.len() + pending.len() > MAX_RETAINED_OBJECTS {
                return Err("seal_closure_limit".to_owned());
            }
            let batch = pending.iter().take(256).cloned().collect::<Vec<_>>();
            for seal_id in &batch {
                pending.remove(seal_id);
            }
            let request = PeerSealResolveRequestBody {
                realm_id: realm_id.clone(),
                seal_refs: batch,
                history_traversal_access: Some(access.clone()),
            };
            let outcome: SealResolveOutcome = self
                .peer_json(replica, "QUERY", "/_arkret/peer/seals/resolve", &request)
                .await?;
            outcome
                .validate_for_peer_request(&request)
                .map_err(|error| format!("seal_outcome:{error}"))?;
            if !outcome.missing_seal_refs.is_empty() {
                return Err("seal_dependency_missing".to_owned());
            }
            for seal in outcome.seals {
                if seal.realm_id != *realm_id {
                    return Err("seal_cross_realm".to_owned());
                }
                if !trusted_base_leaves.contains(&seal.id) {
                    for predecessor in &seal.predecessor_refs {
                        if !trusted_base_leaves.contains(predecessor)
                            && !seals.contains_key(predecessor)
                        {
                            pending.insert(predecessor.clone());
                        }
                    }
                }
                if seals.insert(seal.id.clone(), seal).is_some() {
                    return Err("seal_duplicate".to_owned());
                }
            }
        }
        let event_digests = seals
            .values()
            .filter(|seal| !trusted_base_leaves.contains(&seal.id))
            .flat_map(|seal| seal.delta.iter().cloned())
            .collect::<BTreeSet<_>>();
        if seals.len() + event_digests.len() > MAX_RETAINED_OBJECTS {
            return Err("retained_object_limit".to_owned());
        }
        let mut events = BTreeMap::<Hash, Event>::new();
        for batch in event_digests
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .chunks(1_024)
        {
            let request = PeerEventsResolveRequestBody {
                realm_id: realm_id.clone(),
                event_ids: Vec::new(),
                event_digests: batch.to_vec(),
                include_payload: Some(true),
                max_response_bytes: Some(MAX_RESPONSE_BYTES as u32),
                history_traversal_access: Some(access.clone()),
                directory_source_ref_access: None,
            };
            let outcome: PeerEventsResolveOutcome = self
                .peer_json(replica, "QUERY", "/_arkret/peer/events/resolve", &request)
                .await?;
            outcome
                .validate_for_request(&request)
                .map_err(|error| format!("event_outcome:{error}"))?;
            if !outcome.missing_event_ids.is_empty() || !outcome.missing_event_digests.is_empty() {
                return Err("event_dependency_missing".to_owned());
            }
            for submission in outcome.events {
                let event = submission.event;
                let matching = batch
                    .iter()
                    .filter(|expected| {
                        expected.digest_suite().is_ok_and(|digest_suite| {
                            event
                                .event_digest_with_digest_suite(digest_suite)
                                .ok()
                                .and_then(|digest| Hash::new(digest).ok())
                                .is_some_and(|actual| actual == **expected)
                        })
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                let [digest] = matching.as_slice() else {
                    return Err("event_digest_selector_ambiguous".to_owned());
                };
                if events.insert(digest.clone(), event).is_some() {
                    return Err("event_digest_duplicate".to_owned());
                }
            }
        }
        validate_container_event(replica, events.values())?;
        if !events
            .values()
            .any(|event| event.event_id == replica.archive.accepted_key_evidence_ref)
        {
            return Err("accepted_key_evidence_missing".to_owned());
        }

        let seal_values = seals.values().cloned().collect::<Vec<_>>();
        let event_values = events.values().cloned().collect::<Vec<_>>();
        let cut_seals = seal_values
            .iter()
            .filter(|seal| !trusted_base_leaves.contains(&seal.id))
            .cloned()
            .collect::<Vec<_>>();
        let mut selectors = governance_runtime_dependency_selector_coordinates_for_acquisition(
            &cut_seals,
            &event_values,
        )
        .map_err(|error| format!("dependency_selectors:{error}"))?;
        let mut dependencies = BTreeMap::<(String, Vec<u8>), GovernanceDependency>::new();
        loop {
            selectors.sort_by_key(|selector| {
                selector
                    .canonical_sort_key()
                    .expect("validated governance dependency selector")
            });
            selectors.dedup();
            let missing = selectors
                .into_iter()
                .filter(|selector| {
                    selector
                        .canonical_sort_key()
                        .is_ok_and(|key| !dependencies.contains_key(&(key.0.to_owned(), key.1)))
                })
                .collect::<Vec<_>>();
            if missing.is_empty() {
                break;
            }
            if dependencies.len() + missing.len() > 1_024 {
                return Err("governance_dependency_limit".to_owned());
            }
            let request = PeerGovernanceDependencyResolveRequest {
                realm_id: realm_id.clone(),
                selectors: missing,
                byte_limit: MAX_RESPONSE_BYTES as u64,
                history_traversal_access: Some(access.clone()),
            };
            let outcome: GovernanceDependencyResolveOutcome = self
                .peer_json(
                    replica,
                    "POST",
                    "/_arkret/peer/seals/governance-dependencies",
                    &request,
                )
                .await?;
            outcome
                .validate_for_peer_request(&request)
                .map_err(|error| format!("dependency_outcome:{error}"))?;
            if !outcome.missing_selectors.is_empty() {
                return Err("governance_dependency_missing".to_owned());
            }
            for item in outcome.items {
                let key = item
                    .selector()
                    .canonical_sort_key()
                    .map(|(kind, bytes)| (kind.to_owned(), bytes))
                    .map_err(|error| format!("dependency_key:{error}"))?;
                dependencies.insert(key, item);
            }
            selectors = next_dependency_selectors(dependencies.values())?;
        }
        let dependency_values = dependencies.into_values().collect::<Vec<_>>();
        arkret::verify_mls_governance_cut(
            &base_checkpoint,
            target_basis,
            &cut_seals,
            &event_values,
            &dependency_values,
            |event, _digest_suite, evidence, dependencies| {
                arkret::verify_agent_historical_event_key(
                    event,
                    evidence,
                    dependencies,
                    |request| {
                        super::super::governance_history::verify_agent_history_trust(
                            &self.state,
                            request,
                        )
                    },
                )
            },
        )
        .map_err(|error| format!("checkpoint_replay:{error}"))?;
        Ok(VerifiedClosure {
            seals: seal_values,
            events: event_values,
            dependencies: dependency_values,
        })
    }

    async fn peer_json<Request, Outcome>(
        &self,
        replica: &OrganizationRecoveryArchiveReplica,
        method: &str,
        path: &str,
        request: &Request,
    ) -> Result<Outcome, String>
    where
        Request: Serialize,
        Outcome: DeserializeOwned,
    {
        let route = super::federation::resolved_peer_target(
            &self.state,
            replica.source_id.as_str(),
            "station",
            false,
        )
        .await
        .map_err(|error| format!("service_route:{error}"))?;
        if let Some(reason) = crate::security::federation_outbound_trust_domain_denial(
            replica.source_id.as_str(),
            Some(route.trust_domain.as_str()),
        ) {
            return Err(format!("trust_domain_denied:{reason}"));
        }
        let target = format!("{}{}", route.base_url, path);
        let body = arkret_canonical::canonical_json_bytes(request)
            .map_err(|error| format!("canonical_request:{error}"))?;
        let (url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
            &target,
            "RRK traversal acquisition",
            self.state.config().development_mode,
            REQUEST_TIMEOUT,
        )
        .map_err(|error| format!("egress_policy:{error}"))?;
        let headers = signed_headers(
            &self.state,
            replica.source_id.as_str(),
            route.trust_domain.as_str(),
            method,
            &target,
            &body,
        );
        let method = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|error| format!("http_method:{error}"))?;
        let mut response = client
            .request(method, url)
            .headers(headers)
            .body(body)
            .send()
            .await
            .map_err(|error| format!("network:{error}"))?;
        if !response.status().is_success() {
            return Err(format!("http_status:{}", response.status().as_u16()));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| format!("response_body:{error}"))?
        {
            if bytes.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err("response_limit".to_owned());
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).map_err(|error| format!("response_json:{error}"))
    }
}

struct VerifiedClosure {
    seals: Vec<Seal>,
    events: Vec<Event>,
    dependencies: Vec<GovernanceDependency>,
}

pub(crate) async fn fetch_peer_governance_dependencies(
    state: &AppState,
    source_id: &arkret_wire::DidCoreId,
    request: &PeerGovernanceDependencyResolveRequest,
) -> Result<GovernanceDependencyResolveOutcome, String> {
    let route =
        super::federation::resolved_peer_target(state, source_id.as_str(), "station", false)
            .await
            .map_err(|error| format!("service_route:{error}"))?;
    if let Some(reason) = crate::security::federation_outbound_trust_domain_denial(
        source_id.as_str(),
        Some(route.trust_domain.as_str()),
    ) {
        return Err(format!("trust_domain_denied:{reason}"));
    }
    let path = "/_arkret/peer/seals/governance-dependencies";
    let target = format!("{}{}", route.base_url, path);
    let body = arkret_canonical::canonical_json_bytes(request)
        .map_err(|error| format!("canonical_request:{error}"))?;
    let (url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        &target,
        "history source signer evidence resolution",
        state.config().development_mode,
        REQUEST_TIMEOUT,
    )
    .map_err(|error| format!("egress_policy:{error}"))?;
    let headers = signed_headers(
        state,
        source_id.as_str(),
        route.trust_domain.as_str(),
        "POST",
        &target,
        &body,
    );
    let mut response = client
        .post(url)
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(|error| format!("network:{error}"))?;
    if !response.status().is_success() {
        return Err(format!("http_status:{}", response.status().as_u16()));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("response_body:{error}"))?
    {
        if bytes.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err("response_limit".to_owned());
        }
        bytes.extend_from_slice(&chunk);
    }
    let outcome: GovernanceDependencyResolveOutcome =
        serde_json::from_slice(&bytes).map_err(|error| format!("response_json:{error}"))?;
    outcome
        .validate_for_peer_request(request)
        .map_err(|error| format!("dependency_outcome:{error}"))?;
    Ok(outcome)
}

fn next_dependency_selectors<'a>(
    items: impl Iterator<Item = &'a GovernanceDependency>,
) -> Result<Vec<GovernanceDependencySelector>, String> {
    let items = items.collect::<Vec<_>>();
    let evidence = items
        .into_iter()
        .filter_map(|item| match item {
            GovernanceDependency::AuthenticatedSignerResolutionEvidence {
                authenticated_signer_resolution_evidence,
                ..
            } => Some(authenticated_signer_resolution_evidence.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    governance_attester_evidence_selectors(&evidence)
        .map_err(|error| format!("attester_evidence_selectors:{error}"))
}

fn validate_container_event<'a>(
    replica: &OrganizationRecoveryArchiveReplica,
    events: impl Iterator<Item = &'a Event>,
) -> Result<(), String> {
    let event = events
        .filter(|event| event.event_id == replica.container_event_ref)
        .collect::<Vec<_>>();
    let [event] = event.as_slice() else {
        return Err("container_event_not_exactly_once".to_owned());
    };
    let embedded = event
        .payload
        .get("organization_recovery_archive")
        .ok_or_else(|| "container_archive_missing".to_owned())?;
    if embedded
        != &serde_json::to_value(&replica.archive)
            .map_err(|error| format!("archive_json:{error}"))?
    {
        return Err("container_archive_mismatch".to_owned());
    }
    match event.kind {
        EventKind::MlsCommit => {
            if event
                .payload
                .get("next_epoch")
                .and_then(serde_json::Value::as_u64)
                != Some(replica.archive.epoch)
                || event
                    .payload
                    .get("commit_digest")
                    .and_then(serde_json::Value::as_str)
                    != Some(replica.archive.transition_digest.as_str())
            {
                return Err("container_commit_binding_mismatch".to_owned());
            }
        }
        EventKind::MlsGenesis => {
            if replica.archive.epoch != 0 {
                return Err("container_genesis_epoch_mismatch".to_owned());
            }
            let digest =
                arkret_models_collaboration::events_payloads::mls::mls_genesis_transition_digest(
                    &serde_json::to_value(&event.payload)
                        .map_err(|error| format!("genesis_transition:{error}"))?,
                )
                .map_err(|error| format!("genesis_transition:{error}"))?;
            if digest != replica.archive.transition_digest {
                return Err("container_genesis_binding_mismatch".to_owned());
            }
        }
        _ => return Err("container_event_kind_mismatch".to_owned()),
    }
    Ok(())
}

fn retained_write(
    replica: &OrganizationRecoveryArchiveReplica,
    digest: &Hash,
    closure: VerifiedClosure,
) -> Result<HistoryTraversalRetentionWrite, String> {
    let mut objects = closure
        .seals
        .into_iter()
        .map(HistoryTraversalRetainedObject::Seal)
        .chain(
            closure
                .events
                .into_iter()
                .map(HistoryTraversalRetainedObject::ControlEvent),
        )
        .chain(
            closure
                .dependencies
                .into_iter()
                .map(HistoryTraversalRetainedObject::GovernanceDependency),
        )
        .collect::<Vec<_>>();
    objects.sort_by_key(|object| {
        soland_storage::history_traversal_retained_object_canonical(object)
            .map(|canonical| {
                (
                    canonical.object_kind,
                    canonical.object_ref,
                    canonical.object_digest.to_string(),
                )
            })
            .expect("verified retained object remains canonical")
    });
    if objects.len() > MAX_RETAINED_OBJECTS {
        return Err("retained_object_limit".to_owned());
    }
    let pins = objects
        .iter()
        .map(|object| {
            let canonical = soland_storage::history_traversal_retained_object_canonical(object)
                .map_err(|error| format!("retained_object:{error}"))?;
            match object {
                HistoryTraversalRetainedObject::Seal(seal) => Ok(HistoryTraversalPin::Seal {
                    seal_id: seal.id.clone(),
                    object_digest: canonical.object_digest,
                }),
                HistoryTraversalRetainedObject::ControlEvent(_event) => {
                    let event_digest = Hash::new(canonical.object_ref.clone())
                        .map_err(|error| format!("retained_event_digest:{error}"))?;
                    Ok(HistoryTraversalPin::ControlEvent {
                        event_digest,
                        object_digest: canonical.object_digest,
                    })
                }
                HistoryTraversalRetainedObject::GovernanceDependency(item) => {
                    Ok(HistoryTraversalPin::GovernanceDependency {
                        selector: item.selector().clone(),
                        object_digest: canonical.object_digest,
                    })
                }
            }
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(HistoryTraversalRetentionWrite {
        access: HistoryTraversalAccess::SelfAccess(SelfHistoryTraversalAccess::ArchiveReplica {
            archive_replica_digest: digest.clone(),
        }),
        retention: replica.history_traversal_retention.clone(),
        pins,
        objects,
    })
}

fn signed_headers(
    state: &AppState,
    peer_id: &str,
    peer_trust_domain: &str,
    method: &str,
    target: &str,
    body: &[u8],
) -> HeaderMap {
    if method == "QUERY" {
        return super::frontier_exchange::signed_query_headers(
            state,
            peer_id,
            peer_trust_domain,
            target,
            body,
        );
    }
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    super::outbox::insert_header_if_valid(
        &mut headers,
        "content-digest",
        &super::outbox::content_digest_header_value(body),
    );
    super::outbox::insert_header_if_valid(&mut headers, "source-service-id", state.service_id());
    super::outbox::insert_header_if_valid(&mut headers, "destination-service-id", peer_id);
    super::outbox::insert_header_if_valid(
        &mut headers,
        "source-trust-domain",
        state.config().trust_domain.as_str(),
    );
    super::outbox::insert_header_if_valid(
        &mut headers,
        "destination-trust-domain",
        peer_trust_domain,
    );
    super::outbox::rfc9421_sign(state, headers, method, target)
}

fn retry_delay(attempt_count: u64) -> chrono::Duration {
    let seconds = 5_u64
        .saturating_mul(1_u64 << attempt_count.min(8))
        .min(30 * 60);
    chrono::Duration::seconds(seconds as i64)
}

fn stable_error_code(error: &str) -> &str {
    error.split(':').next().unwrap_or("rrk_acquisition_failed")
}
