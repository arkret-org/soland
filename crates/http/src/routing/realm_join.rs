//! Authenticated Realm join preparation.
//!
//! This boundary turns holder-Station state into the exact governance facts
//! and complete unsigned Event a not-yet-member device may sign. It never accepts a
//! Directory candidate, endpoint, or caller-supplied governance basis.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration as StdDuration, Instant};

use arkret_models_collaboration::governance::membership_invite::{
    InviteAcceptPayload, JoinGateProof, MembershipPayload, MembershipPayloadState,
};
use arkret_models_collaboration::governance::realm_join_intake::{
    RealmJoinBootstrapOutcome, RealmJoinBootstrapRequestBody, RealmJoinGovernanceFacts,
    RealmJoinIntent, RealmJoinPrepareOutcome, RealmJoinPrepareRequestBody, RealmJoinTransition,
    RealmJoinUnsignedEvent,
};
use arkret_schema::InviteLiveTargetSlot;
use arkret_wire::{
    ActorId, CellRef, EncryptionProfile, ErrorCode, Event, JoinRule, Precondition, Predicate,
    PredicateOp,
};
use salvo::http::StatusCode;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};

use crate::routing::events::event_log::VerifiedActorPredecessors;
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
mod pages;
use arkret_models_collaboration::governance::realm_join_bootstrap::{
    RealmJoinBootstrapAssembly, RealmJoinBootstrapContinuation, RealmJoinBootstrapReadRequest,
    RealmJoinBootstrapRecord,
};

const PREPARE_TTL_MINUTES: i64 = 5;
const PEER_BOOTSTRAP_TIMING_BUCKET: StdDuration = StdDuration::from_millis(80);
const PEER_BOOTSTRAP_REQUEST_TIMEOUT: StdDuration = StdDuration::from_secs(30);
const MAX_BOOTSTRAP_CANDIDATES: usize = 16;

struct RemoteJoinContext {
    governance_facts: RealmJoinGovernanceFacts,
    transition: RealmJoinTransition,
    verified_predecessors: Vec<Event>,
    expires_at: chrono::DateTime<chrono::Utc>,
}

pub(super) fn self_router() -> Router {
    Router::new().push(Router::with_path("realm-joins/prepare").post(prepare))
}

pub(super) fn peer_router() -> Router {
    Router::new().push(Router::with_path("realm-joins/bootstrap").post(peer_bootstrap))
}

fn realm_join_not_found() -> AppError {
    AppError::not_found("Realm join bootstrap not found")
}

fn member_state_cell(account_id: &arkret_wire::AccountId) -> Result<CellRef, AppError> {
    let actor = ActorId::account(account_id.clone());
    let subject = arkret_wire::composite_subject(&[actor
        .canonical_key()
        .map_err(|error| AppError::param_invalid(error.to_string()))?])
    .map_err(validation)?;
    CellRef::new(format!("ak:cell:ak.component.member.state.v1:{subject}"))
        .map_err(|error| AppError::param_invalid(error.to_string()))
}

fn invite_lifecycle_cell(invite_id: &arkret_wire::InviteId) -> Result<CellRef, AppError> {
    CellRef::new(format!(
        "ak:cell:ak.component.invite.lifecycle.v1:{invite_id}"
    ))
    .map_err(|error| AppError::param_invalid(error.to_string()))
}

async fn applicant_predecessors(
    state: &AppState,
    realm_id: &arkret_wire::RealmId,
    applicant: &arkret_wire::AccountId,
) -> Result<Vec<Event>, AppError> {
    let actor = ActorId::account(applicant.clone());
    let records = state
        .event_queries()
        .canonical_events_for_realm_actor(realm_id.as_str(), &actor.to_string())
        .await
        .map_err(|error| AppError::internal(format!("Realm join predecessor lookup: {error}")))?;
    let Some(highest) = records.iter().map(|record| record.actor_seq).max() else {
        return Ok(Vec::new());
    };
    let mut events = records
        .into_iter()
        .filter(|record| record.actor_seq == highest)
        .map(|record| {
            serde_json::from_value::<Event>(record.envelope).map_err(|error| {
                AppError::internal(format!("stored Realm join predecessor is invalid: {error}"))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    events.sort_by(|left, right| left.event_id.cmp(&right.event_id));
    events.dedup_by(|left, right| left.event_id == right.event_id);
    Ok(events)
}

#[salvo::oapi::endpoint(operation_id = "ak.peer.realm_join.read.bootstrap", tags("realm_join"))]
#[tracing::instrument(skip_all, fields(op = "ak.peer.realm_join.read.bootstrap.v1"))]
async fn peer_bootstrap(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RealmJoinBootstrapOutcome> {
    let started_at = Instant::now();
    let outcome = peer_bootstrap_inner(depot, req).await;
    if let Some(remaining) = PEER_BOOTSTRAP_TIMING_BUCKET.checked_sub(started_at.elapsed()) {
        tokio::time::sleep(remaining).await;
    }
    outcome
}

async fn peer_bootstrap_inner(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RealmJoinBootstrapOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    crate::routing::events::peer::validate_peer_request(state, req, true).await?;
    let source_id = crate::routing::events::peer::source_id_from_request(req)?;
    let request = req
        .parse_json::<RealmJoinBootstrapReadRequest>()
        .await
        .map_err(|_| AppError::json_invalid("invalid bootstrap request"))?;
    let digest = if matches!(request, RealmJoinBootstrapReadRequest::Initial(_)) {
        Some(
            RealmJoinBootstrapRequestBody::request_digest_for_canonical(
                req.payload()
                    .await
                    .map_err(|e| AppError::json_invalid(e.to_string()))?,
            )
            .map_err(validation)?,
        )
    } else {
        None
    };
    json_ok(pages::serve(state, &source_id, request, digest).await?)
}

async fn bootstrap_candidate_service_ids(
    state: &AppState,
    body: &RealmJoinPrepareRequestBody,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<arkret_wire::DidCoreId>, AppError> {
    let mut candidates = match &body.intent {
        RealmJoinIntent::InviteAccept {
            invite_id,
            invite_token,
        } => {
            let expected_invitee = body.account_id.to_string();
            let invite = state
                .realm_invites()
                .get(invite_id.as_str())
                .await
                .map_err(|error| AppError::internal(format!("Realm invite lookup: {error}")))?
                .filter(|invite| {
                    invite.realm_id == body.realm_id.as_str()
                        && invite.invitee_id.as_deref() == Some(expected_invitee.as_str())
                        && invite.invite_token == invite_token.as_str()
                        && matches!(invite.status.as_str(), "pending" | "claimed")
                        && invite.expires_at.is_none_or(|expiry| expiry > now)
                })
                .ok_or_else(|| AppError::not_found("Realm join preparation not found"))?;
            let inviter = serde_json::from_str::<arkret_wire::AccountId>(&invite.inviter_id)
                .map_err(|_| {
                    crate::app_error!(
                        FrontierUnavailable,
                        "signed invite has no routable inviter account",
                    )
                })?;
            vec![inviter.station_id]
        }
        RealmJoinIntent::MemberJoin { .. } | RealmJoinIntent::Knock {} => state
            .projections()
            .snapshot()
            .members_of_realm(body.realm_id.as_str())
            .into_iter()
            .filter(|member| member.state == "join")
            .filter_map(|member| serde_json::from_str::<ActorId>(&member.member).ok())
            .map(|actor| actor.route_service_id().clone())
            .collect(),
    };
    candidates.retain(|candidate| candidate.as_str() != state.service_id());
    candidates.sort();
    candidates.dedup();
    candidates.truncate(MAX_BOOTSTRAP_CANDIDATES);
    if candidates.is_empty() {
        return Err(crate::app_error!(
            FrontierUnavailable,
            "no authorized Realm join bootstrap candidate is available",
        ));
    }
    Ok(candidates)
}

static BOOTSTRAP_DOWNLOAD_WORK: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

async fn fetch_peer_bootstrap(
    state: &AppState,
    candidate: &arkret_wire::DidCoreId,
    request: &RealmJoinBootstrapRequestBody,
) -> Result<RealmJoinBootstrapAssembly, AppError> {
    let _work = BOOTSTRAP_DOWNLOAD_WORK
        .try_acquire()
        .map_err(|_| crate::app_error!(RateLimited, "bootstrap download already in flight"))?;
    use arkret_models_collaboration::governance::realm_join_bootstrap::MAX_BOOTSTRAP_PAGES_PER_ATTEMPT;
    let handle = format!(
        "realm-join-download:{}",
        arkret_canonical::canonical_sha256(&(candidate, request))
            .map_err(|e| AppError::internal(e.to_string()))?
    );
    let mut assembly = state
        .sync()
        .realm_join_download(&handle)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    for _ in 0..MAX_BOOTSTRAP_PAGES_PER_ATTEMPT {
        let next = match &assembly {
            Some(current) => match &current.next_cursor {
                Some(cursor) => {
                    RealmJoinBootstrapReadRequest::Continue(RealmJoinBootstrapContinuation {
                        cursor: cursor.clone(),
                    })
                }
                None => {
                    current
                        .finish(crate::wire::now())
                        .map_err(|e| AppError::internal(e.to_string()))?;
                    return Ok(assembly.expect("complete assembly"));
                }
            },
            None => RealmJoinBootstrapReadRequest::Initial(request.clone()),
        };
        let page = fetch_peer_bootstrap_page(state, candidate, &next).await?;
        match &mut assembly {
            Some(current) => current
                .append(page, request)
                .map_err(|e| AppError::internal(e.to_string()))?,
            None => {
                assembly = Some(
                    RealmJoinBootstrapAssembly::new(page, request)
                        .map_err(|e| AppError::internal(e.to_string()))?,
                )
            }
        }
        let current = assembly.as_ref().expect("received first page");
        state
            .sync()
            .save_realm_join_download(&handle, current)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
    }
    if let Some(current) = assembly.filter(|a| a.next_cursor.is_none()) {
        current
            .finish(crate::wire::now())
            .map_err(|e| AppError::internal(e.to_string()))?;
        return Ok(current);
    }
    Err(crate::app_error!(
        LimitExceeded,
        "bootstrap download work budget reached; retry resumes retained progress"
    ))
}

async fn fetch_peer_bootstrap_page(
    state: &AppState,
    candidate: &arkret_wire::DidCoreId,
    request: &RealmJoinBootstrapReadRequest,
) -> Result<RealmJoinBootstrapOutcome, AppError> {
    use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue};

    let route = crate::routing::federation::resolved_peer_route(
        state,
        candidate.as_str(),
        "station",
        false,
    )
    .await
    .map_err(|error| crate::app_error!(FrontierUnavailable, error))?;
    if let Some(reason) = crate::security::federation_outbound_trust_domain_denial(
        candidate.as_str(),
        Some(route.trust_domain.as_str()),
    ) {
        return Err(crate::app_error!(FrontierUnavailable, reason));
    }
    let target = format!(
        "{}/_arkret/peer/realm-joins/bootstrap",
        route.base_url().trim_end_matches('/')
    );
    let body = arkret_canonical::canonical_json_bytes(request)
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    let (url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        &target,
        "Realm join bootstrap",
        state.config().development_mode,
        PEER_BOOTSTRAP_REQUEST_TIMEOUT,
    )
    .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    crate::routing::federation::outbox::insert_header_if_valid(
        &mut headers,
        "content-digest",
        &crate::routing::federation::outbox::content_digest_header_value(&body),
    );
    crate::routing::federation::outbox::insert_header_if_valid(
        &mut headers,
        "source-service-id",
        state.service_id(),
    );
    crate::routing::federation::outbox::insert_header_if_valid(
        &mut headers,
        "destination-service-id",
        candidate.as_str(),
    );
    crate::routing::federation::outbox::insert_header_if_valid(
        &mut headers,
        "source-trust-domain",
        state.config().trust_domain.as_str(),
    );
    crate::routing::federation::outbox::insert_header_if_valid(
        &mut headers,
        "destination-trust-domain",
        route.trust_domain.as_str(),
    );
    let headers = crate::routing::federation::outbox::rfc9421_sign(state, headers, "POST", &target);
    let mut response = client
        .post(url)
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    if !response.status().is_success() {
        return Err(crate::app_error!(
            FrontierUnavailable,
            "Realm join bootstrap candidate did not return usable evidence",
        ));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?
    {
        if bytes.len() + chunk.len() > RealmJoinBootstrapOutcome::MAX_CANONICAL_BYTES {
            return Err(crate::app_error!(
                LimitExceeded,
                "Realm join bootstrap response exceeds the protocol limit",
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    let outcome = serde_json::from_slice::<RealmJoinBootstrapOutcome>(&bytes)
        .map_err(|_| crate::app_error!(FrontierUnavailable, "invalid Realm join bootstrap"))?;
    outcome.validate_structural().map_err(validation)?;
    Ok(outcome)
}

fn insert_bootstrap_material<T: Clone + PartialEq>(
    entries: &mut BTreeMap<String, T>,
    key: String,
    value: &T,
    what: &str,
) -> Result<(), AppError> {
    if let Some(previous) = entries.insert(key, value.clone())
        && previous != *value
    {
        return Err(crate::app_error!(
            FrontierUnavailable,
            format!("one {what} identifier resolves to different bytes"),
        ));
    }
    Ok(())
}

fn join_rule_from_verified_values(
    values: &BTreeMap<CellRef, serde_json::Value>,
    join_rule_cell: &CellRef,
    genesis_cell: &CellRef,
) -> JoinRule {
    let value = values
        .get(join_rule_cell)
        .or_else(|| values.get(genesis_cell));
    let rule = value.and_then(|value| {
        value.as_str().or_else(|| {
            value
                .get("value")
                .or_else(|| value.get("default_join_rule"))
                .or_else(|| value.get("join_rule"))
                .or_else(|| value.pointer("/object/default_join_rule"))
                .or_else(|| value.pointer("/object/join_rule"))
                .or_else(|| value.pointer("/value/default_join_rule"))
                .or_else(|| value.pointer("/value/join_rule"))
                .and_then(serde_json::Value::as_str)
        })
    });
    join_rule(rule.unwrap_or("invite"))
}

fn encryption_profile_from_verified_genesis(
    values: &BTreeMap<CellRef, serde_json::Value>,
    genesis_cell: &CellRef,
) -> Result<EncryptionProfile, AppError> {
    let genesis = values.get(genesis_cell).ok_or_else(|| {
        crate::app_error!(
            FrontierUnavailable,
            "verified Realm bootstrap has no genesis state",
        )
    })?;
    let profile = genesis
        .get("encryption_profile")
        .or_else(|| genesis.pointer("/object/encryption_profile"))
        .ok_or_else(|| {
            crate::app_error!(
                FrontierUnavailable,
                "verified Realm genesis has no encryption profile",
            )
        })?;
    serde_json::from_value(profile.clone()).map_err(|_| {
        crate::app_error!(
            FrontierUnavailable,
            "verified Realm encryption profile is invalid",
        )
    })
}

fn member_state_core_with_expected(
    realm_id: &arkret_wire::RealmId,
    member_id: ActorId,
    membership: MembershipPayloadState,
    gate_proofs: Vec<JoinGateProof>,
    expected: serde_json::Value,
) -> Result<RealmJoinTransition, AppError> {
    let subject = arkret_wire::composite_subject(&[member_id
        .canonical_key()
        .map_err(|error| AppError::param_invalid(error.to_string()))?])
    .map_err(validation)?;
    let cell_id = CellRef::new(format!("ak:cell:ak.component.member.state.v1:{subject}"))
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let payload = MembershipPayload {
        strand_id: None,
        realm_id: Some(realm_id.clone()),
        member_id,
        membership,
        gate_proofs,
        reason: None,
        membership_cause: None,
        agent_controller_binding: None,
        invite_ref: None,
    };
    Ok(RealmJoinTransition::MemberState {
        payload,
        preconditions: vec![Precondition {
            cell_id,
            predicate: Predicate {
                op: PredicateOp::HeadEq,
                value: Some(expected),
                values: None,
                predicate_id: None,
            },
        }],
    })
}

async fn verify_bootstrap_predecessors(
    state: &AppState,
    realm_id: &arkret_wire::RealmId,
    applicant: &arkret_wire::AccountId,
    events: &[Event],
) -> Result<Vec<Event>, AppError> {
    if events.is_empty() {
        return Ok(Vec::new());
    }
    let actor = ActorId::account(applicant.clone());
    let remote_seq = events[0].actor_seq;
    if events.iter().any(|event| event.actor_seq != remote_seq) {
        return Err(crate::app_error!(
            FrontierUnavailable,
            "Realm join predecessor response mixes actor sequences",
        ));
    }
    for event in events {
        if event.realm_id != *realm_id || event.actor_id != actor {
            return Err(crate::app_error!(
                FrontierUnavailable,
                "Realm join predecessor crosses the requested Realm or actor",
            ));
        }
        let digest_suite = event
            .event_id
            .event_digest()
            .digest_suite()
            .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
        crate::routing::events::event_log::verify_federated_event_admission(
            state,
            event,
            digest_suite,
        )
        .await
        .map_err(|error| crate::app_error!(FrontierUnavailable, error))?;
    }

    let records = state
        .event_queries()
        .canonical_events_for_realm_actor(realm_id.as_str(), &actor.to_string())
        .await
        .map_err(|error| AppError::internal(format!("actor frontier unavailable: {error}")))?;
    if remote_seq > 0 {
        for event in events {
            let mut continues_actor = false;
            for predecessor_id in &event.prev_refs {
                let predecessor = state
                    .event_queries()
                    .canonical_event(predecessor_id.as_str())
                    .await
                    .map_err(|error| {
                        AppError::internal(format!("actor predecessor unavailable: {error}"))
                    })?
                    .ok_or_else(|| {
                        crate::app_error!(
                            FrontierUnavailable,
                            "Realm join predecessor dependency is not locally accepted",
                        )
                    })?;
                if predecessor.realm_id.as_deref() != Some(realm_id.as_str()) {
                    return Err(crate::app_error!(
                        FrontierUnavailable,
                        "Realm join predecessor dependency crosses the Realm boundary",
                    ));
                }
                if predecessor.actor_id == actor.to_string()
                    && predecessor.actor_seq.checked_add(1) == Some(remote_seq)
                {
                    continues_actor = true;
                }
            }
            if !continues_actor {
                return Err(crate::app_error!(
                    FrontierUnavailable,
                    "Realm join predecessor does not continue accepted actor history",
                ));
            }
        }
    }
    let local_max = records.iter().map(|record| record.actor_seq).max();
    match local_max {
        None if remote_seq == 0 && events.iter().all(|event| event.prev_refs.is_empty()) => {}
        None => {
            return Err(crate::app_error!(
                FrontierUnavailable,
                "Realm join predecessor continuity is unavailable locally",
            ));
        }
        Some(local_max) if remote_seq > local_max.saturating_add(1) => {
            return Err(crate::app_error!(
                FrontierUnavailable,
                "Realm join predecessor leaves an unverified actor history gap",
            ));
        }
        Some(local_max) if remote_seq == local_max.saturating_add(1) => {
            let local_heads = records
                .iter()
                .filter(|record| record.actor_seq == local_max)
                .map(|record| record.event_id.as_str())
                .collect::<BTreeSet<_>>();
            if events.iter().any(|event| {
                let remote_refs = event
                    .prev_refs
                    .iter()
                    .map(|event_id| event_id.as_str())
                    .collect::<BTreeSet<_>>();
                !local_heads.is_subset(&remote_refs)
            }) {
                return Err(crate::app_error!(
                    FrontierUnavailable,
                    "Realm join predecessor does not continue the complete local frontier",
                ));
            }
        }
        Some(_) => {}
    }
    Ok(events.to_vec())
}

async fn verify_peer_bootstrap(
    state: &AppState,
    request: &RealmJoinBootstrapRequestBody,
    outcome: RealmJoinBootstrapAssembly,
) -> Result<RemoteJoinContext, AppError> {
    outcome.finish(crate::wire::now()).map_err(validation)?;
    outcome.validate_closure_coordinates().map_err(validation)?;
    let records = &outcome.records;
    let outcome = &outcome.first;
    if outcome.expires_at <= crate::wire::now() {
        return Err(crate::app_error!(
            FrontierUnavailable,
            "Realm join bootstrap evidence has expired",
        ));
    }

    let mut seals = BTreeMap::new();
    let mut events = BTreeMap::new();
    let mut dependencies = Vec::new();
    let mut predecessors = Vec::new();
    for record in records {
        match record {
            RealmJoinBootstrapRecord::SealConclusion { .. } => {
                return Err(crate::app_error!(
                    FrontierUnavailable,
                    "Seal conclusions require an independently authenticated signer configuration"
                ));
            }
            RealmJoinBootstrapRecord::Seal { seal } => {
                insert_bootstrap_material(&mut seals, seal.id.to_string(), seal, "Realm join Seal")?
            }
            RealmJoinBootstrapRecord::ControlMove { event } => insert_bootstrap_material(
                &mut events,
                event.event_id.to_string(),
                event,
                "Realm join Control Move",
            )?,
            RealmJoinBootstrapRecord::GovernanceDependency { dependency } => {
                dependencies.push(dependency.clone())
            }
            RealmJoinBootstrapRecord::ApplicantPredecessor { event } => {
                predecessors.push(event.clone())
            }
        }
    }
    // Page traversal order is independent of the verifier's canonical selector order.
    let mut dependencies = dependencies
        .into_iter()
        .map(|dependency| {
            let key = dependency
                .selector()
                .canonical_sort_key()
                .map_err(validation)?;
            Ok((key, dependency))
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    dependencies.sort_by(|left, right| left.0.cmp(&right.0));
    let dependencies = dependencies
        .into_iter()
        .map(|(_, dependency)| dependency)
        .collect::<Vec<_>>();
    predecessors.sort_by(|a, b| a.event_id.cmp(&b.event_id));
    let seals = seals.into_values().collect::<Vec<_>>();
    let events = events.into_values().collect::<Vec<_>>();
    let verified = arkret::verify_mls_governance_closure(
        &request.realm_id,
        &outcome.governance_facts.seal_basis,
        &seals,
        &events,
        &dependencies,
        crate::routing::governance_history::historical_governance_key_verifier(state.clone()),
    )
    .await
    .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    if verified.checkpoint.live_digest_suite != outcome.governance_facts.digest_algorithm {
        return Err(crate::app_error!(
            FrontierUnavailable,
            "Realm join bootstrap reports the wrong live digest suite",
        ));
    }

    let join_rule_cell = CellRef::new("ak:cell:ak.component.realm.join_rule.v1:null".to_owned())
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    let genesis_cell = CellRef::new(arkret_wire::REALM_GENESIS_CELL.to_owned())
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    let intent_cell = match &request.intent {
        RealmJoinIntent::InviteAccept { .. } => {
            arkret_schema::invite_live_target_cell(&request.applicant_account_id)
                .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?
        }
        RealmJoinIntent::MemberJoin { .. } | RealmJoinIntent::Knock {} => {
            member_state_cell(&request.applicant_account_id)?
        }
    };
    let lifecycle_cell = match &request.intent {
        RealmJoinIntent::InviteAccept { invite_id, .. } => Some(invite_lifecycle_cell(invite_id)?),
        RealmJoinIntent::MemberJoin { .. } | RealmJoinIntent::Knock {} => None,
    };
    let mut requested_cells = vec![
        join_rule_cell.clone(),
        genesis_cell.clone(),
        intent_cell.clone(),
    ];
    requested_cells.extend(lifecycle_cell.iter().cloned());
    let registry = arkret_lattice_registry::try_build_sdk_state_registry()
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    let values = arkret_state::mls_governance_proof::materialize_registered_cell_values_at_basis_from_verified_checkpoint(
        &verified.checkpoint,
        &outcome.governance_facts.seal_basis,
        &requested_cells,
        &registry,
        arkret::project_control_writes_at_state,
    )
    .await
    .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;

    let verified_rule = join_rule_from_verified_values(&values, &join_rule_cell, &genesis_cell);
    if verified_rule != outcome.governance_facts.join_rule
        || !rule_allows_intent(
            match verified_rule {
                JoinRule::Public => "public",
                JoinRule::Invite => "invite",
                JoinRule::Knock => "knock",
                JoinRule::Restricted => "restricted",
                JoinRule::KnockRestricted => "knock_restricted",
                JoinRule::Closed => "closed",
            },
            &request.intent,
        )
    {
        return Err(crate::app_error!(
            FrontierUnavailable,
            "Realm join bootstrap reports an unusable join rule",
        ));
    }
    let verified_encryption = encryption_profile_from_verified_genesis(&values, &genesis_cell)?;
    if verified_encryption != outcome.governance_facts.encryption_profile {
        return Err(crate::app_error!(
            FrontierUnavailable,
            "Realm join bootstrap reports the wrong encryption profile",
        ));
    }
    let transition = match &request.intent {
        RealmJoinIntent::InviteAccept { invite_id, .. } => {
            let invite_move = verified
                .checkpoint
                .accepted_events
                .iter()
                .find(|e| {
                    e.kind == arkret_wire::EventKind::InviteCreate
                        && arkret_wire::InviteId::from_event_id(&e.event_id) == *invite_id
                })
                .ok_or_else(|| {
                    crate::app_error!(FrontierUnavailable, "verified invite create missing")
                })?;
            if values.get(&intent_cell)
                != Some(&serde_json::Value::String(invite_move.event_id.to_string()))
            {
                return Err(crate::app_error!(
                    FrontierUnavailable,
                    "directed invite is not live"
                ));
            }
            let invitee = invite_move
                .payload
                .get("invitee_account_id")
                .cloned()
                .and_then(|v| serde_json::from_value::<arkret_wire::AccountId>(v).ok());
            if invitee.as_ref() != Some(&request.applicant_account_id)
                || !values
                    .get(lifecycle_cell.as_ref().expect("invite lifecycle"))
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|s| matches!(s, "pending" | "claimed"))
            {
                return Err(crate::app_error!(
                    FrontierUnavailable,
                    "invalid directed invite target or lifecycle"
                ));
            }
            invite_accept_core(invite_id.clone(), request.applicant_account_id.clone())?
        }
        RealmJoinIntent::MemberJoin { gate_proofs } => member_state_core_with_expected(
            &request.realm_id,
            ActorId::account(request.applicant_account_id.clone()),
            MembershipPayloadState::Join,
            gate_proofs.clone(),
            values
                .get(&intent_cell)
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        )?,
        RealmJoinIntent::Knock {} => member_state_core_with_expected(
            &request.realm_id,
            ActorId::account(request.applicant_account_id.clone()),
            MembershipPayloadState::Knock,
            vec![],
            values
                .get(&intent_cell)
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        )?,
    };
    let verified_predecessors = verify_bootstrap_predecessors(
        state,
        &request.realm_id,
        &request.applicant_account_id,
        &predecessors,
    )
    .await?;
    Ok(RemoteJoinContext {
        governance_facts: RealmJoinGovernanceFacts {
            join_rule: verified_rule,
            seal_basis: outcome.governance_facts.seal_basis.clone(),
            digest_algorithm: verified.checkpoint.live_digest_suite,
            encryption_profile: verified_encryption,
        },
        transition,
        verified_predecessors,
        expires_at: outcome.expires_at,
    })
}

async fn remote_join_context(
    state: &AppState,
    body: &RealmJoinPrepareRequestBody,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<RemoteJoinContext, AppError> {
    let request = RealmJoinBootstrapRequestBody {
        request_id: body.request_id.clone(),
        realm_id: body.realm_id.clone(),
        applicant_account_id: body.account_id.clone(),
        intent: body.intent.clone(),
    };
    request.validate().map_err(validation)?;
    let candidates = bootstrap_candidate_service_ids(state, body, now).await?;
    for candidate in candidates {
        let outcome = match fetch_peer_bootstrap(state, &candidate, &request).await {
            Ok(outcome) => outcome,
            Err(error) => {
                tracing::debug!(%candidate, %error, "Realm join bootstrap fetch unavailable");
                continue;
            }
        };
        match verify_peer_bootstrap(state, &request, outcome).await {
            Ok(context) => return Ok(context),
            Err(error) => {
                tracing::debug!(%candidate, %error, "Realm join bootstrap verification failed");
            }
        }
    }
    Err(crate::app_error!(
        FrontierUnavailable,
        "no authorized Realm join bootstrap candidate returned verifiable evidence",
    ))
}

async fn require_prepare_device_active(
    state: &AppState,
    selector: &soland_storage::DeviceRevocationGateSelector,
) -> Result<(), AppError> {
    let status = state
        .persistence()
        .device_revocation_gate_status(selector)
        .await
        .map_err(|e| AppError::internal(format!("join authoring device gate failed: {e}")))?;
    status.ensure_allowed().map_err(|e| {
        AppError::capability_denied(format!("join authoring device is no longer active: {e}"))
    })
}

fn validation(error: arkret_wire::WireError) -> AppError {
    AppError::from_rejection(
        error.error_code().unwrap_or(ErrorCode::SchemaViolation),
        error.to_string(),
    )
}

fn join_rule(value: &str) -> JoinRule {
    match value {
        "public" => JoinRule::Public,
        "knock" => JoinRule::Knock,
        "restricted" => JoinRule::Restricted,
        "knock_restricted" => JoinRule::KnockRestricted,
        "closed" => JoinRule::Closed,
        _ => JoinRule::Invite,
    }
}

fn rule_allows_intent(rule: &str, intent: &RealmJoinIntent) -> bool {
    match intent {
        RealmJoinIntent::InviteAccept { .. } => true,
        RealmJoinIntent::MemberJoin { .. } => {
            matches!(rule, "public" | "restricted" | "knock_restricted")
        }
        RealmJoinIntent::Knock {} => matches!(rule, "knock" | "knock_restricted"),
    }
}

fn invite_accept_core(
    invite_id: arkret_wire::InviteId,
    account_id: arkret_wire::AccountId,
) -> Result<RealmJoinTransition, AppError> {
    let precondition = InviteLiveTargetSlot::held_by_invite(&invite_id)
        .precondition(&account_id)
        .map_err(|error| AppError::internal(format!("invite live-target cell: {error}")))?;
    Ok(RealmJoinTransition::InviteAccept {
        payload: InviteAcceptPayload::directed(invite_id, account_id),
        preconditions: vec![precondition],
    })
}

async fn member_state_core(
    state: &AppState,
    realm_id: &arkret_wire::RealmId,
    seal_basis: &arkret_wire::SealBasis,
    member_id: ActorId,
    membership: MembershipPayloadState,
    gate_proofs: Vec<JoinGateProof>,
) -> Result<RealmJoinTransition, AppError> {
    let subject = arkret_wire::composite_subject(&[member_id
        .canonical_key()
        .map_err(|error| AppError::param_invalid(error.to_string()))?])
    .map_err(validation)?;
    let cell_id =
        arkret_wire::CellRef::new(format!("ak:cell:ak.component.member.state.v1:{subject}"))
            .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let expected = state
        .projections()
        .effective_state_at(&seal_basis.leaves, realm_id)
        .await
        .map_err(|error| {
            crate::app_error!(
                FrontierUnavailable,
                format!("verified member state is unavailable: {error}"),
            )
        })?
        .get(&cell_id)
        .cloned()
        .and_then(arkret_state::state_model::ResolvedCellState::into_value)
        .unwrap_or(serde_json::Value::Null);
    let payload = MembershipPayload {
        strand_id: None,
        realm_id: Some(realm_id.clone()),
        member_id,
        membership,
        gate_proofs,
        reason: None,
        membership_cause: None,
        agent_controller_binding: None,
        invite_ref: None,
    };
    Ok(RealmJoinTransition::MemberState {
        payload,
        preconditions: vec![Precondition {
            cell_id,
            predicate: Predicate {
                op: PredicateOp::HeadEq,
                value: Some(expected),
                values: None,
                predicate_id: None,
            },
        }],
    })
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.realm_join.command.prepare",
    tags("realm_join")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm_join.command.prepare.v1"))]
async fn prepare(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<RealmJoinPrepareRequestBody>,
) -> JsonResult<RealmJoinPrepareOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let authenticated_account =
        crate::routing::identity::auth_grant_dpop::authenticated_session_account_id(
            state, &session,
        )
        .await?;
    let body = body.into_inner();
    body.validate().map_err(validation)?;
    if body.account_id != authenticated_account
        || body.account_id.station_id.as_str() != state.service_id()
    {
        return Err(AppError::not_found("Realm join preparation not found"));
    }

    let generation =
        crate::routing::identity::device_generation::active_device_revocation_gate_selector(
            state,
            authenticated_account.principal_id.as_str(),
            &session.device_id,
        )
        .await
        .map_err(|error| {
            AppError::conflict(format!("join authoring device unavailable: {error}"))
        })?;
    let authenticated_actor = ActorId::account(authenticated_account.clone());
    let request_hash = arkret_canonical::canonical_sha256(&body).map_err(|error| {
        crate::app_error!(
            SchemaViolation,
            format!("Realm join preparation request cannot be canonicalized: {error}"),
        )
    })?;
    let scoped_request_id = format!(
        "{}:{}:{}",
        session.device_id, generation.target_device_generation_ref, body.request_id
    );
    let idempotency_key = scoped_request_id.as_str();
    let operation_id = arkret_wire::ServiceOperationId::SELF_REALM_JOIN_COMMAND_PREPARE_V1;
    match state
        .jobs()
        .scoped_idempotency_record(&authenticated_actor, operation_id, idempotency_key)
        .await
        .map_err(|error| AppError::internal(format!("Realm join preparation lookup: {error}")))?
    {
        Some(record) if record.request_hash == request_hash => {
            let outcome = serde_json::from_value(record.response_body).map_err(|error| {
                AppError::internal(format!("stored Realm join preparation is invalid: {error}"))
            })?;
            require_prepare_device_active(state, &generation).await?;
            return json_ok(outcome);
        }
        Some(_) => {
            return Err(crate::app_error!(
                DuplicateConflict,
                "request_id is already bound to another Realm join preparation",
            ));
        }
        None => {}
    }

    let observed_at = crate::wire::now();
    let mut leaves = state
        .projections()
        .realm_seal_basis_leaves(&body.realm_id)
        .await
        .map_err(|_| {
            crate::app_error!(
                FrontierUnavailable,
                "verified Realm join frontier is unavailable",
            )
        })?;
    leaves.sort();
    leaves.dedup();
    let seal_basis = arkret_wire::SealBasis { leaves };
    let context = if seal_basis.leaves.is_empty() {
        remote_join_context(state, &body, observed_at).await?
    } else {
        if seal_basis.leaves.len() != 1 {
            return Err(crate::app_error!(
                FrontierUnavailable,
                "verified Realm join frontier must have exactly one head",
            ));
        }
        seal_basis.validate_protocol_bounds().map_err(|_| {
            crate::app_error!(
                FrontierUnavailable,
                "verified Realm join frontier is unavailable",
            )
        })?;
        let rule = crate::routing::spaces::directory::realm_resolution::realm_join_rule(
            state,
            body.realm_id.as_str(),
        );
        let mut intent_expiry = None;
        match &body.intent {
            RealmJoinIntent::InviteAccept {
                invite_id,
                invite_token,
            } => {
                let expected_invitee = authenticated_account.to_string();
                let invite = state
                    .realm_invites()
                    .get(invite_id.as_str())
                    .await
                    .map_err(|error| AppError::internal(format!("Realm invite lookup: {error}")))?
                    .filter(|invite| {
                        invite.realm_id == body.realm_id.as_str()
                            && invite.status == "pending"
                            && invite.invitee_id.as_deref() == Some(expected_invitee.as_str())
                            && invite.invite_token == invite_token.as_str()
                            && invite
                                .expires_at
                                .is_none_or(|expires_at| expires_at > observed_at)
                    })
                    .ok_or_else(|| AppError::not_found("Realm join preparation not found"))?;
                intent_expiry = invite.expires_at;
                match crate::routing::spaces::space::invite_token_realm_resolution(
                    state,
                    invite_token,
                )
                .await
                {
                    crate::routing::spaces::space::InviteTokenRealmResolution::Ready {
                        realm_id,
                        seal_basis: invite_basis,
                    } if realm_id == body.realm_id.as_str() && invite_basis == seal_basis => {}
                    crate::routing::spaces::space::InviteTokenRealmResolution::FrontierUnavailable => {
                        return Err(crate::app_error!(
                            FrontierUnavailable,
                            "verified Realm join frontier is unavailable",
                        ));
                    }
                    _ => return Err(AppError::not_found("Realm join preparation not found")),
                }
            }
            RealmJoinIntent::MemberJoin { .. }
                if rule_allows_intent(rule.as_str(), &body.intent) => {}
            RealmJoinIntent::Knock {} if rule_allows_intent(rule.as_str(), &body.intent) => {}
            RealmJoinIntent::MemberJoin { .. } | RealmJoinIntent::Knock {} => {
                return Err(AppError::not_found("Realm join preparation not found"));
            }
        }
        let transition = match &body.intent {
            RealmJoinIntent::InviteAccept { invite_id, .. } => {
                invite_accept_core(invite_id.clone(), authenticated_account.clone())?
            }
            RealmJoinIntent::MemberJoin { gate_proofs } => {
                member_state_core(
                    state,
                    &body.realm_id,
                    &seal_basis,
                    authenticated_actor.clone(),
                    MembershipPayloadState::Join,
                    gate_proofs.clone(),
                )
                .await?
            }
            RealmJoinIntent::Knock {} => {
                member_state_core(
                    state,
                    &body.realm_id,
                    &seal_basis,
                    authenticated_actor.clone(),
                    MembershipPayloadState::Knock,
                    Vec::new(),
                )
                .await?
            }
        };
        let digest_algorithm = state
            .projections()
            .seal_basis_digest_suite(&body.realm_id, &seal_basis.leaves)
            .await
            .map_err(|_| {
                crate::app_error!(
                    FrontierUnavailable,
                    "verified Realm join digest suite is unavailable",
                )
            })?;
        let encryption_profile: EncryptionProfile = state
            .projections()
            .snapshot()
            .realm_encryption_profile(body.realm_id.as_str())
            .and_then(|value| serde_json::from_value(serde_json::Value::String(value)).ok())
            .ok_or_else(|| {
                crate::app_error!(
                    FrontierUnavailable,
                    "verified Realm encryption profile is unavailable",
                )
            })?;
        RemoteJoinContext {
            governance_facts: RealmJoinGovernanceFacts {
                join_rule: join_rule(&rule),
                seal_basis,
                digest_algorithm,
                encryption_profile,
            },
            transition,
            verified_predecessors: Vec::new(),
            expires_at: intent_expiry
                .map(|expiry| {
                    expiry.min(observed_at + chrono::Duration::minutes(PREPARE_TTL_MINUTES))
                })
                .unwrap_or_else(|| observed_at + chrono::Duration::minutes(PREPARE_TTL_MINUTES)),
        }
    };
    let observed_actor_frontier = crate::routing::events::event_log::load_realm_actor_frontier(
        state,
        body.realm_id.clone(),
        authenticated_actor.clone(),
        VerifiedActorPredecessors::from_verified(&context.verified_predecessors),
    )
    .await?;
    // The Realm may exist only in this verified bootstrap context, not in local projections.
    let accepted_actor_frontier =
        arkret_models_collaboration::event_sync::RealmActorFrontierView::new(
            observed_actor_frontier.realm_id,
            observed_actor_frontier.actor_id,
            observed_actor_frontier.next_actor_seq,
            observed_actor_frontier.frontier_event_ids,
            context.governance_facts.digest_algorithm,
        )
        .map_err(validation)?;
    let unsigned_event = RealmJoinUnsignedEvent::prepare(
        &body,
        &accepted_actor_frontier,
        context.governance_facts.seal_basis.clone(),
        context.transition,
        context.governance_facts.digest_algorithm,
    )
    .map_err(validation)?;
    let outcome = RealmJoinPrepareOutcome {
        request_id: body.request_id.clone(),
        account_id: authenticated_account,
        realm_id: body.realm_id.clone(),
        request_digest: body.request_digest().map_err(validation)?,
        governance_facts: context.governance_facts,
        unsigned_event,
        accepted_actor_frontier,
        authoring_device_generation_ref: generation.target_device_generation_ref,
        observed_at,
        expires_at: context.expires_at,
    };
    outcome.validate_for_request(&body).map_err(validation)?;
    require_prepare_device_active(state, &generation).await?;
    let response_body = serde_json::to_value(&outcome)
        .map_err(|error| AppError::internal(format!("Realm join preparation encode: {error}")))?;
    state
        .jobs()
        .store_idempotency_record(soland_services::jobs::IdempotencyState {
            authenticated_actor: authenticated_actor.clone(),
            operation_id: operation_id.to_owned(),
            idempotency_key: idempotency_key.to_owned(),
            request_hash: request_hash.clone(),
            response_status: StatusCode::OK.as_u16() as i32,
            response_body,
            created_at: observed_at,
            expires_at: outcome.expires_at,
        })
        .await
        .map_err(|error| AppError::internal(format!("Realm join preparation persist: {error}")))?;
    let landed = state
        .jobs()
        .scoped_idempotency_record(&authenticated_actor, operation_id, idempotency_key)
        .await
        .map_err(|error| AppError::internal(format!("Realm join preparation replay: {error}")))?
        .ok_or_else(|| AppError::internal("Realm join preparation was not persisted"))?;
    if landed.request_hash != request_hash {
        return Err(crate::app_error!(
            DuplicateConflict,
            "request_id lost a concurrent Realm join preparation race",
        ));
    }
    let landed_outcome = serde_json::from_value(landed.response_body).map_err(|error| {
        AppError::internal(format!(
            "persisted Realm join preparation is invalid: {error}"
        ))
    })?;
    require_prepare_device_active(state, &generation).await?;
    json_ok(landed_outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directed_invite_core_freezes_live_target_precondition() {
        let invite_id = arkret_wire::InviteId::new(
            "ak:invite:ARbUzETAsZ3suuQ0GSmBWTsNjmUnTEEl_ZnDOUWRPm-N".to_owned(),
        )
        .unwrap();
        let account_id = arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:station.example".to_owned()).unwrap(),
        );
        let core = invite_accept_core(invite_id.clone(), account_id.clone()).unwrap();
        let RealmJoinTransition::InviteAccept {
            payload,
            preconditions,
        } = core
        else {
            panic!("wrong authoring branch")
        };
        assert_eq!(payload.invite_id, invite_id);
        assert_eq!(payload.invitee_account_id.as_ref(), Some(&account_id));
        assert_eq!(preconditions.len(), 1);
        assert_eq!(
            preconditions[0].cell_id,
            arkret_schema::invite_live_target_cell(&account_id).unwrap()
        );
    }

    #[test]
    fn join_rules_select_only_the_registered_intents() {
        let join = RealmJoinIntent::MemberJoin {
            gate_proofs: Vec::new(),
        };
        let knock = RealmJoinIntent::Knock {};
        assert!(rule_allows_intent("public", &join));
        assert!(rule_allows_intent("restricted", &join));
        assert!(rule_allows_intent("knock_restricted", &join));
        assert!(!rule_allows_intent("invite", &join));
        assert!(rule_allows_intent("knock", &knock));
        assert!(rule_allows_intent("knock_restricted", &knock));
        assert!(!rule_allows_intent("public", &knock));
        assert!(!rule_allows_intent("closed", &knock));
    }

    #[test]
    fn applicant_member_cell_binds_the_complete_account() {
        let principal =
            arkret_wire::DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap();
        let first = arkret_wire::AccountId::new(
            principal.clone(),
            arkret_wire::DidCoreId::new("ak:did_core:web:first.example".to_owned()).unwrap(),
        );
        let second = arkret_wire::AccountId::new(
            principal,
            arkret_wire::DidCoreId::new("ak:did_core:web:second.example".to_owned()).unwrap(),
        );
        assert_ne!(
            member_state_cell(&first).unwrap(),
            member_state_cell(&second).unwrap()
        );
    }

    #[test]
    fn verified_join_rule_cell_overrides_genesis_default() {
        let join_rule_cell =
            CellRef::new("ak:cell:ak.component.realm.join_rule.v1:null".to_owned()).unwrap();
        let genesis_cell = CellRef::new(arkret_wire::REALM_GENESIS_CELL.to_owned()).unwrap();
        let values = BTreeMap::from([
            (
                genesis_cell.clone(),
                serde_json::json!({"default_join_rule": "invite"}),
            ),
            (
                join_rule_cell.clone(),
                serde_json::json!({"value": "knock_restricted"}),
            ),
        ]);
        assert_eq!(
            join_rule_from_verified_values(&values, &join_rule_cell, &genesis_cell),
            JoinRule::KnockRestricted
        );
    }
}
