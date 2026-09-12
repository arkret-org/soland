//! Request-bound, expiring traversal state; never an accepted governance write.
use std::collections::VecDeque;

use arkret_models_collaboration::governance::realm_join_bootstrap::*;
use arkret_models_collaboration::governance_dependencies::{
    GovernanceDependencySelector,
    governance_runtime_dependency_selector_coordinates_for_acquisition,
};
use arkret_server::{CursorAuthority, CursorBindingContext};
use serde::{Deserialize, Serialize};

use super::*;

static PAGE_WORK: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

#[derive(Clone, Debug, Serialize, Deserialize)]
enum Pending {
    Seal(arkret_wire::SealId),
    Event(arkret_wire::Hash),
    Dependency(GovernanceDependencySelector),
    Applicant(Event),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Traversal {
    request: RealmJoinBootstrapRequestBody,
    request_digest: arkret_wire::Hash,
    facts: RealmJoinGovernanceFacts,
    observed_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
    pending: VecDeque<Pending>,
    seen: BTreeSet<String>,
    page_index: u32,
    bytes: usize,
}

fn internal(error: impl std::fmt::Display) -> AppError {
    AppError::internal(error.to_string())
}
fn cursor_error(error: impl std::fmt::Display) -> AppError {
    crate::app_error!(CursorExpired, error.to_string())
}
fn authority_cursor_error(error: arkret_server::CursorAuthorityError) -> AppError {
    match error {
        arkret_server::CursorAuthorityError::Expired => cursor_error("bootstrap cursor expired"),
        _ => crate::app_error!(CursorIntegrityInvalid, error.to_string()),
    }
}
fn context(state: &AppState, traversal: &Traversal) -> Result<CursorBindingContext, AppError> {
    Ok(CursorBindingContext::new(
        traversal.request.applicant_account_id.to_string(),
        None,
        state.service_core_id(),
        arkret_canonical::canonical_sha256(&(
            "realm_join_bootstrap",
            &traversal.request,
            &traversal.request_digest,
            &traversal.facts,
            traversal.observed_at,
            traversal.expires_at,
        ))
        .map_err(internal)?,
    ))
}

async fn mint(state: &AppState, traversal: &Traversal) -> Result<String, AppError> {
    let ttl = (traversal.expires_at - crate::wire::now()).num_milliseconds();
    if ttl <= 0 {
        return Err(cursor_error("bootstrap expired"));
    }
    let (token, record) = CursorAuthority::mint_stream(
        context(state, traversal)?,
        serde_json::to_value(traversal).map_err(internal)?,
        ttl,
    )
    .map_err(authority_cursor_error)?;
    state
        .sync()
        .upsert_cursor(&soland_services::sync::CursorState {
            handle: record.handle,
            binding_subject: Some(record.context.binding_subject),
            device_id: None,
            service_id: record.context.service_id,
            filter_digest: Some(record.context.filter_digest),
            purpose: "stream".into(),
            positions: Some(record.positions),
            target: None,
            issued_at_ms: record.issued_at_ms,
            expires_at_ms: record.expires_at_ms,
        })
        .await
        .map_err(internal)?;
    Ok(token)
}

pub(super) async fn serve(
    state: &AppState,
    source: &str,
    request: RealmJoinBootstrapReadRequest,
    initial_digest: Option<arkret_wire::Hash>,
) -> Result<RealmJoinBootstrapOutcome, AppError> {
    request.validate().map_err(validation)?;
    let _work = PAGE_WORK
        .try_acquire()
        .map_err(|_| crate::app_error!(RateLimited, "bootstrap page work already in flight",))?;
    let (mut traversal, key) = match request {
        RealmJoinBootstrapReadRequest::Initial(request) => {
            if request.applicant_account_id.station_id.as_str() != source {
                return Err(realm_join_not_found());
            }
            rate_limit(state, &request, source)?;
            let expiry = authorize(state, &request).await?;
            let request_digest =
                initial_digest.ok_or_else(|| internal("missing canonical initial digest"))?;
            let key = format!("bootstrap:{}", request.request_id);
            if let Some(page) = cached(state, &request, &request_digest, &key).await? {
                return Ok(page);
            }
            let mut leaves = state
                .projections()
                .realm_seal_basis_leaves(&request.realm_id)
                .await
                .map_err(internal)?;
            leaves.sort();
            leaves.dedup();
            if leaves.len() != 1 {
                return Err(crate::app_error!(
                    FrontierUnavailable,
                    "bootstrap requires one accepted Realm authority head",
                ));
            }
            let seal_basis = arkret_wire::SealBasis { leaves };
            seal_basis.validate_protocol_bounds().map_err(validation)?;
            let digest_algorithm = state
                .projections()
                .seal_basis_digest_suite(&request.realm_id, &seal_basis.leaves)
                .await
                .map_err(internal)?;
            let encryption_profile = state
                .projections()
                .snapshot()
                .realm_encryption_profile(request.realm_id.as_str())
                .and_then(|v| serde_json::from_value(serde_json::Value::String(v)).ok())
                .ok_or_else(|| {
                    crate::app_error!(
                        FrontierUnavailable,
                        "bootstrap encryption profile unavailable",
                    )
                })?;
            let rule = crate::routing::spaces::directory::realm_resolution::realm_join_rule(
                state,
                request.realm_id.as_str(),
            );
            let mut pending: VecDeque<_> = seal_basis
                .leaves
                .iter()
                .cloned()
                .map(Pending::Seal)
                .collect();
            pending.extend(
                applicant_predecessors(state, &request.realm_id, &request.applicant_account_id)
                    .await?
                    .into_iter()
                    .map(Pending::Applicant),
            );
            let observed_at = crate::wire::now();
            (
                Traversal {
                    request,
                    request_digest,
                    facts: RealmJoinGovernanceFacts {
                        join_rule: join_rule(&rule),
                        seal_basis,
                        digest_algorithm,
                        encryption_profile,
                    },
                    observed_at,
                    expires_at: expiry
                        .unwrap_or(observed_at + chrono::Duration::seconds(300))
                        .min(observed_at + chrono::Duration::seconds(300)),
                    pending,
                    seen: BTreeSet::new(),
                    page_index: 0,
                    bytes: 0,
                },
                key,
            )
        }
        RealmJoinBootstrapReadRequest::Continue(request) => {
            let cursor =
                CursorAuthority::decode_stream(&request.cursor).map_err(authority_cursor_error)?;
            let stored = state
                .sync()
                .cursor(&cursor.h)
                .await
                .map_err(internal)?
                .ok_or_else(|| cursor_error("bootstrap cursor unavailable"))?;
            let record = soland_http::util::cursor_binding_record_from_state(stored)
                .map_err(authority_cursor_error)?;
            let traversal: Traversal =
                serde_json::from_value(record.positions.clone()).map_err(cursor_error)?;
            if traversal.request.applicant_account_id.station_id.as_str() != source {
                return Err(realm_join_not_found());
            }
            CursorAuthority::resolve_stream(&cursor, &context(state, &traversal)?, Some(&record))
                .map_err(authority_cursor_error)?;
            rate_limit(state, &traversal.request, source)?;
            authorize(state, &traversal.request).await?;
            let key = format!("bootstrap-page:{}", cursor.h);
            if let Some(page) =
                cached(state, &traversal.request, &traversal.request_digest, &key).await?
            {
                return Ok(page);
            }
            (traversal, key)
        }
    };
    let mut page = RealmJoinBootstrapOutcome {
        request_id: traversal.request.request_id.clone(),
        realm_id: traversal.request.realm_id.clone(),
        applicant_account_id: traversal.request.applicant_account_id.clone(),
        request_digest: traversal.request_digest.clone(),
        governance_facts: traversal.facts.clone(),
        page_index: traversal.page_index,
        records: vec![],
        next_cursor: None,
        observed_at: traversal.observed_at,
        expires_at: traversal.expires_at,
    };
    let mut page_bytes = arkret_canonical::canonical_json_bytes(&page)
        .map_err(internal)?
        .len()
        + 8192;
    for _ in 0..MAX_BOOTSTRAP_PAGE_STEPS {
        if page.records.len() == MAX_BOOTSTRAP_PAGE_RECORDS {
            break;
        }
        let Some(next) = traversal.pending.pop_front() else {
            break;
        };
        let (record, edges) = resolve(state, &traversal.request.realm_id, &next).await?;
        let record_key = record.key().map_err(validation)?;
        if traversal.seen.contains(&record_key) {
            continue;
        }
        record
            .validate_scope(
                &traversal.request.realm_id,
                &traversal.request.applicant_account_id,
            )
            .map_err(validation)?;
        let size = arkret_canonical::canonical_json_bytes(&record)
            .map_err(internal)?
            .len()
            + 1;
        if page_bytes + size > RealmJoinBootstrapOutcome::MAX_CANONICAL_BYTES {
            if page.records.is_empty() {
                return Err(crate::app_error!(
                    LimitExceeded,
                    "bootstrap record exceeds one page",
                ));
            }
            traversal.pending.push_front(next);
            break;
        }
        if traversal.seen.len() >= MAX_BOOTSTRAP_RECORDS
            || traversal.bytes + size > MAX_BOOTSTRAP_BYTES
            || traversal.pending.len() + edges.len() > MAX_BOOTSTRAP_RECORDS
        {
            return Err(crate::app_error!(
                LimitExceeded,
                "bootstrap context budget exhausted; prior cursor remains resumable",
            ));
        }
        traversal.seen.insert(record_key);
        traversal.pending.extend(edges);
        traversal.bytes += size;
        page_bytes += size;
        page.records.push(record);
    }
    traversal.page_index += 1;
    let retained_overhead = arkret_canonical::canonical_json_bytes(&traversal)
        .map_err(internal)?
        .len()
        + 8192;
    if traversal.bytes + retained_overhead > MAX_BOOTSTRAP_BYTES {
        return Err(crate::app_error!(
            LimitExceeded,
            "bootstrap retained context budget exhausted; prior cursor retained",
        ));
    }
    traversal.bytes += retained_overhead;
    if !traversal.pending.is_empty() {
        page.next_cursor = Some(mint(state, &traversal).await?);
    }
    page.validate_for_request_digest(&traversal.request, &traversal.request_digest)
        .map_err(validation)?;
    authorize(state, &traversal.request).await?;
    state
        .jobs()
        .store_idempotency_record(soland_services::jobs::IdempotencyState {
            authenticated_actor: ActorId::account(traversal.request.applicant_account_id.clone()),
            operation_id: "ak.peer.realm_join.read.bootstrap.v1".into(),
            idempotency_key: key.clone(),
            request_hash: traversal.request_digest.to_string(),
            response_status: 200,
            response_body: serde_json::to_value(&page).map_err(internal)?,
            created_at: page.observed_at,
            expires_at: page.expires_at,
        })
        .await
        .map_err(internal)?;
    cached(state, &traversal.request, &traversal.request_digest, &key)
        .await?
        .ok_or_else(|| cursor_error("bootstrap page was not retained"))
}

async fn cached(
    state: &AppState,
    request: &RealmJoinBootstrapRequestBody,
    digest: &arkret_wire::Hash,
    key: &str,
) -> Result<Option<RealmJoinBootstrapOutcome>, AppError> {
    let record = state
        .jobs()
        .scoped_idempotency_record(
            &ActorId::account(request.applicant_account_id.clone()),
            "ak.peer.realm_join.read.bootstrap.v1",
            key,
        )
        .await
        .map_err(internal)?;
    let Some(record) = record else {
        return Ok(None);
    };
    if record.request_hash != digest.as_str() {
        return Err(crate::app_error!(
            DuplicateConflict,
            "bootstrap request identity already bound",
        ));
    }
    if record.expires_at <= crate::wire::now() {
        return Err(cursor_error("bootstrap expired"));
    }
    let page: RealmJoinBootstrapOutcome =
        serde_json::from_value(record.response_body).map_err(internal)?;
    page.validate_for_request_digest(request, digest)
        .map_err(validation)?;
    Ok(Some(page))
}

fn rate_limit(
    state: &AppState,
    request: &RealmJoinBootstrapRequestBody,
    source: &str,
) -> Result<(), AppError> {
    if state.realm_join_bootstrap_rate_limited(
        request.realm_id.as_str(),
        &request.applicant_account_id.to_string(),
    ) {
        return Err(crate::app_error!(
            RateLimited,
            "bootstrap read budget exceeded",
        ));
    }
    if state.realm_join_bootstrap_rate_limited("bootstrap-source", source) {
        return Err(crate::app_error!(
            RateLimited,
            "bootstrap source budget exceeded",
        ));
    }
    Ok(())
}

async fn authorize(
    state: &AppState,
    request: &RealmJoinBootstrapRequestBody,
) -> Result<Option<chrono::DateTime<chrono::Utc>>, AppError> {
    let now = crate::wire::now();
    let proofs = match &request.intent {
        RealmJoinIntent::MemberJoin { gate_proofs } => {
            serde_json::to_value(gate_proofs).map_err(internal)?
        }
        _ => serde_json::json!([]),
    };
    {
        let projection = state.projections().snapshot();
        if projection.realm_is_in_terminal_state(request.realm_id.as_str())
            || projection.realm_ordinary_writes_blocked(request.realm_id.as_str())
        {
            return Err(realm_join_not_found());
        }
        projection
            .check_join_request_gates(
                request.realm_id.as_str(),
                &ActorId::account(request.applicant_account_id.clone()).to_string(),
                !matches!(request.intent, RealmJoinIntent::MemberJoin { .. }),
                true,
                proofs.as_array().expect("proof array"),
                now,
            )
            .map_err(|_| realm_join_not_found())?;
    }
    if matches!(request.intent, RealmJoinIntent::MemberJoin { .. }) {
        let value = serde_json::json!({"payload":{"membership":"join","gate_proofs":proofs}});
        crate::routing::events::event_log::validate_join_gate_proof_signatures(
            value.as_object().expect("object"),
            state,
        )
        .await
        .map_err(|_| realm_join_not_found())?;
    }
    match &request.intent {
        RealmJoinIntent::InviteAccept {
            invite_id,
            invite_token,
        } => {
            let invitee = request.applicant_account_id.to_string();
            let invite = state
                .realm_invites()
                .get(invite_id.as_str())
                .await
                .map_err(internal)?
                .filter(|i| {
                    i.realm_id == request.realm_id.as_str()
                        && i.invitee_id.as_deref() == Some(invitee.as_str())
                        && i.invite_token == invite_token.as_str()
                        && matches!(i.status.as_str(), "pending" | "claimed")
                        && i.expires_at.is_none_or(|t| t > now)
                })
                .ok_or_else(realm_join_not_found)?;
            Ok(invite.expires_at)
        }
        _ => {
            let rule = crate::routing::spaces::directory::realm_resolution::realm_join_rule(
                state,
                request.realm_id.as_str(),
            );
            if !rule_allows_intent(&rule, &request.intent) {
                return Err(realm_join_not_found());
            }
            Ok(None)
        }
    }
}

async fn resolve(
    state: &AppState,
    realm: &arkret_wire::RealmId,
    pending: &Pending,
) -> Result<(RealmJoinBootstrapRecord, Vec<Pending>), AppError> {
    let mut edges = Vec::new();
    let record = match pending {
        Pending::Seal(id) => {
            let seal = state
                .projections()
                .seal_by_id(id)
                .await
                .map_err(internal)?
                .ok_or_else(|| crate::app_error!(DependencyMissing, "bootstrap Seal missing"))?;
            edges.extend(seal.predecessor_ref.iter().cloned().map(Pending::Seal));
            edges.extend(seal.delta.iter().cloned().map(Pending::Event));
            edges.extend(
                governance_runtime_dependency_selector_coordinates_for_acquisition(
                    std::slice::from_ref(&seal),
                    &[],
                )
                .map_err(validation)?
                .into_iter()
                .map(Pending::Dependency),
            );
            RealmJoinBootstrapRecord::Seal { seal }
        }
        Pending::Event(digest) => {
            let event = state
                .projections()
                .control_event_by_digest(digest)
                .await
                .map_err(internal)?
                .ok_or_else(|| {
                    crate::app_error!(DependencyMissing, "bootstrap Control Move missing",)
                })?;
            edges.extend(
                governance_runtime_dependency_selector_coordinates_for_acquisition(
                    &[],
                    std::slice::from_ref(&event),
                )
                .map_err(validation)?
                .into_iter()
                .map(Pending::Dependency),
            );
            RealmJoinBootstrapRecord::ControlMove { event }
        }
        Pending::Dependency(selector) => {
            let dependency = state
                .persistence()
                .governance_dependency_store()
                .get(realm, selector)
                .await
                .map_err(internal)?
                .ok_or_else(|| {
                    crate::app_error!(DependencyMissing, "bootstrap governance dependency missing",)
                })?;
            edges.extend(
                dependency
                    .dependency_selectors()
                    .map_err(validation)?
                    .into_iter()
                    .map(Pending::Dependency),
            );
            RealmJoinBootstrapRecord::GovernanceDependency { dependency }
        }
        Pending::Applicant(event) => RealmJoinBootstrapRecord::ApplicantPredecessor {
            event: event.clone(),
        },
    };
    Ok((record, edges))
}
