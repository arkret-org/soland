use arkret_models_collaboration::agent_operations::AgentLifecycleState;
use arkret_state::state::store::ControlProposalIngressClass;

use super::*;

#[path = "control_proposal_decisions.rs"]
mod control_proposal_decisions;

/// Resolve governance health with the one Ack-less authority class replayed
/// from its durable ingress classification.
///
/// Persistence records Ack-less Human PCR controls as pending rows carrying
/// the `AcklessSelfPrincipal` classification captured at first admission. The
/// generic projection service cannot resolve device authorization records, so
/// the HTTP boundary replays that stored classification against its stable
/// references and supplies exact revalidated Event digests; every other
/// missing-Ack row remains a fail-closed store error.
/// This service's observation coordinate for a Realm Seal frontier read.
///
/// `event-auth-state-resolution.md` fixes `current` as the serving service's
/// verified durable view at this coordinate, never a global wall-clock latest
/// claim. The sequence is the count of accepted canonical Realm Events this
/// service has durably applied: it is monotone non-decreasing per service and
/// advances exactly when the durable view can change.
pub(crate) async fn realm_seal_frontier_observation_coordinate(
    state: &AppState,
    realm_id: &RealmId,
) -> Result<arkret_models_collaboration::event_sync::RealmSealFrontierObservationCoordinate, AppError>
{
    let service_id = arkret_wire::DidCoreId::new(state.service_id().to_owned())
        .map_err(|error| AppError::internal(format!("serving service DID invalid: {error}")))?;
    let stats = state
        .event_queries()
        .realm_event_stats(realm_id.as_str())
        .await
        .map_err(|error| {
            AppError::internal(format!("Realm observation coordinate unavailable: {error}"))
        })?;
    Ok(
        arkret_models_collaboration::event_sync::RealmSealFrontierObservationCoordinate {
            service_id,
            sequence: stats.count,
            observed_at: chrono::Utc::now(),
        },
    )
}

/// Materialize the serving service's durable current accepted Seal antichain
/// for an already-authorized caller. Visibility checks stay at the self/peer
/// transport boundary.
pub(crate) async fn load_realm_seal_frontier(
    state: &AppState,
    realm_id: &RealmId,
) -> Result<arkret_models_collaboration::event_sync::RealmSealFrontierView, AppError> {
    let head = crate::notary::ensure_realm_seal_head(state, realm_id)
        .await
        .map_err(|error| AppError::internal(format!("seal head unavailable: {error}")))?;
    let stats = state
        .event_queries()
        .realm_event_stats(realm_id.as_str())
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "canonical Realm Event preflight unavailable: {error}"
            ))
        })?;
    if stats.count == 0 {
        return Err(AppError::not_found(
            "realm has no accepted Seal on this deployment",
        ));
    }
    let seal =
        match crate::routing::events::event_log::governance_proof::materialize_realm_event_seal(
            state, realm_id,
        )
        .await
        {
            Ok(view) => view.accepted_seal,
            Err(error) if error.code == ErrorCode::FrontierUnavailable && head.is_some() => {
                head.expect("checked existing Realm Seal head")
            }
            Err(error) => return Err(error),
        };
    let governance_policy = crate::control_proposal::control_proposal_policy(state, realm_id, &[])
        .await
        .map_err(|error| {
            AppError::internal(format!("control governance policy unavailable: {error}"))
        })?;
    let governance_health =
        frontier_control_governance_health(state, realm_id, governance_policy).await?;
    let observation_coordinate =
        realm_seal_frontier_observation_coordinate(state, realm_id).await?;
    Ok(
        arkret_models_collaboration::event_sync::RealmSealFrontierView::new(
            realm_id.clone(),
            arkret_wire::SealBasis {
                leaves: vec![seal.id],
            },
            governance_health,
            observation_coordinate,
        ),
    )
}

pub(crate) async fn frontier_control_governance_health(
    state: &AppState,
    realm_id: &RealmId,
    policy: arkret_wire::ControlProposalDecisionPolicy,
) -> Result<arkret_models_collaboration::event_sync::ControlGovernanceHealth, AppError> {
    let limit =
        arkret_models_collaboration::event_sync::ControlGovernanceHealth::MAX_PENDING_PROPOSALS + 1;
    let pending = state
        .projections()
        .pending_control_records(realm_id, limit)
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "control governance pending rows unavailable: {error}"
            ))
        })?;
    let sealed = state
        .projections()
        .retained_control_proposal_faults(realm_id, limit)
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "control governance sealed rows unavailable: {error}"
            ))
        })?;
    let mut ackless_authorized = std::collections::BTreeSet::new();
    let mut ackless_rejections = Vec::new();
    for (event, ingress_class, digest_suite) in pending
        .iter()
        .filter(|record| record.control_proposal_ack.is_none())
        .map(|record| (&record.event, &record.ingress_class, record.digest_suite))
        .chain(
            sealed
                .iter()
                .filter(|record| record.control_proposal_ack.is_none())
                .map(|record| (&record.event, &record.ingress_class, record.digest_suite)),
        )
    {
        let digest =
            arkret_state::state::control_event_digest(event, digest_suite).map_err(|error| {
                AppError::internal(format!("Ack-less Control Move digest invalid: {error}"))
            })?;
        let rejection = match ingress_class {
            // An Ack-required row without its Ack is the impossible durable
            // state the ingress invariant forbids; surface it as a diagnostic
            // instead of guessing a class from the Event shape.
            ControlProposalIngressClass::AckRequired => Some(
                "Control Move was classified Ack-required at ingress but stored without its Ack",
            ),
            ControlProposalIngressClass::AcklessSelfPrincipal(class) => {
                super::submit::replay_ackless_self_principal_ingress(state, event, class)
                    .await
                    .map_err(|error| {
                        AppError::internal(format!(
                            "Ack-less Control Move authority unavailable: {error}"
                        ))
                    })?
            }
        };
        match rejection {
            None => {
                ackless_authorized.insert(digest);
            }
            Some(reason) => ackless_rejections.push(format!("{reason} @ {}", event.event_id)),
        }
    }
    state
        .projections()
        .control_governance_health_with_ackless_authorities(
            realm_id,
            chrono::Utc::now(),
            policy,
            &ackless_authorized,
        )
        .await
        .map_err(|error| {
            let diagnostic = if ackless_rejections.is_empty() {
                String::new()
            } else {
                format!(
                    "; Ack-less authority revalidation failed: {}",
                    ackless_rejections.join(", ")
                )
            };
            AppError::internal(format!(
                "control governance health unavailable: {error}{diagnostic}"
            ))
        })
}

pub(in crate::routing::events) fn router() -> Router {
    Router::new()
        .push(
            Router::with_path("authorization-leases")
                .post(super::lease_issue::issue_authorization_leases),
        )
        .push(
            Router::with_path("control-proposal-acks")
                .post(super::control_proposal_ack_issue::issue_control_proposal_ack),
        )
        .push(
            Router::with_path("control-proposal-decisions")
                .post(control_proposal_decisions::submit_control_proposal_decision),
        )
        .push(
            Router::with_path("control-proposal-decisions/query")
                .post(control_proposal_decisions::read_control_proposal_decision),
        )
        .push(Router::with_path("events/describe").query(events_describe))
        .push(Router::with_path("events/delivery-status").query(event_delivery_status))
        .push(Router::with_path("events/subscribe").get(super::super::sync::events_subscribe))
        .push(
            Router::with_path("events")
                .post(submit_event)
                .query(super::super::sync::events_read_body),
        )
        .push(Router::with_path("events/resolve").query(resolve_events))
        .push(Router::with_path("events/frontier").query(events_frontier))
        .push(Router::with_path("seals/frontier").query(seals_frontier))
        .push(
            Router::with_path("seals/availability-receipts").post(issue_seal_availability_receipts),
        )
        .push(Router::with_path("seals").post(submit_event_seal))
        .push(
            Router::with_path("seals/mls-governance-proof")
                .post(super::governance_proof::mls_governance_proof),
        )
        .push(Router::with_path("events/{event_id}").get(get_event))
}

const AVAILABILITY_RESERVATION_STATUS: i32 = 102;
const AVAILABILITY_RESERVATION_LEASE_SECONDS: i64 = 30;
const AVAILABILITY_RESERVATION_WAIT_ATTEMPTS: usize = 600;

fn availability_idempotency_outcome(
    record: soland_storage::IdempotencyRecord,
    request: &SealAvailabilityReceiptIssueRequest,
    request_hash: &str,
) -> Result<Option<SealAvailabilityReceiptIssueOutcome>, AppError> {
    if record.request_hash != request_hash {
        return Err(AppError::internal(
            "availability idempotency record binding mismatch",
        ));
    }
    if record.response_status == AVAILABILITY_RESERVATION_STATUS {
        return Ok(None);
    }
    if record.response_status != StatusCode::OK.as_u16() as i32 {
        return Err(AppError::internal(
            "availability idempotency record has an invalid terminal status",
        ));
    }
    let cached =
        serde_json::from_value::<SealAvailabilityReceiptIssueOutcome>(record.response_body)
            .map_err(|error| {
                AppError::internal(format!(
                    "availability idempotency outcome is invalid: {error}"
                ))
            })?;
    cached.validate_for_request(request).map_err(|error| {
        AppError::internal(format!(
            "availability idempotency outcome binding is invalid: {error}"
        ))
    })?;
    Ok(Some(cached))
}

async fn wait_for_availability_idempotency_outcome(
    state: &AppState,
    authenticated_actor: &arkret_wire::ActorId,
    idempotency_key: &str,
    request: &SealAvailabilityReceiptIssueRequest,
    request_hash: &str,
) -> Result<SealAvailabilityReceiptIssueOutcome, AppError> {
    for _ in 0..AVAILABILITY_RESERVATION_WAIT_ATTEMPTS {
        let record = state
            .persistence()
            .scoped_idempotency_record(
                authenticated_actor,
                "ak.self.seals.command.issue_availability_receipts",
                idempotency_key,
            )
            .await
            .map_err(|error| {
                AppError::internal(format!("availability idempotency lookup failed: {error}"))
            })?
            .ok_or_else(|| {
                crate::app_error!(
                    TemporarilyUnavailable,
                    "availability preparation reservation expired before completion",
                )
            })?;
        if let Some(outcome) = availability_idempotency_outcome(record, request, request_hash)? {
            return Ok(outcome);
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    Err(crate::app_error!(
        TemporarilyUnavailable,
        "availability preparation is still being completed by the first writer",
    ))
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.seals.command.issue_availability_receipts",
    tags("events")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.self.seals.command.issue_availability_receipts.v1")
)]
async fn issue_seal_availability_receipts(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<SealAvailabilityReceiptIssueRequest>,
) -> JsonResult<SealAvailabilityReceiptIssueOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    super::super::require_agent_session_scope(
        &session,
        arkret_wire::ServiceOperationId::SELF_SEALS_COMMAND_ISSUE_AVAILABILITY_RECEIPTS_V1,
    )?;
    let request = body.into_inner();
    request
        .validate()
        .map_err(|error| crate::app_error!(SchemaViolation, error.to_string()))?;
    let session_core_id = arkret_wire::DidCoreId::new(session.actor.clone()).map_err(|error| {
        crate::app_error!(
            PolicyViolation,
            format!("availability requester_id DID core id is invalid: {error}"),
        )
    })?;
    let own_pcr = state
        .projections()
        .snapshot()
        .realm_is_principal_control_for_actor(
            request.realm_id.as_str(),
            &crate::routing::identity::session_actor::session_actor_from_credential(
                state, &session,
            )?
            .to_string(),
        );
    let agent = if own_pcr {
        None
    } else {
        crate::routing::identity::agent_pcr::agent_record_for_controller_pcr(
            state,
            &session.actor,
            request.realm_id.as_str(),
        )
        .await?
    };
    if !own_pcr && agent.is_none() {
        return Err(crate::app_error!(
            PolicyViolation,
            "availability preparation is limited to the caller's own or delegated Agent principal-control Realm",
        ));
    }

    let request_hash = canonical::canonical_sha256(&request).map_err(|error| {
        crate::app_error!(
            SchemaViolation,
            format!("availability request is not canonical-hashable: {error}"),
        )
    })?;
    let idempotency_key =
        format!("ak.self.seals.command.issue_availability_receipts.v1:{request_hash}");
    let authenticated_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        session_core_id.clone(),
        state.service_core_id(),
    ));
    state
        .jobs()
        .prune_expired_idempotency(Utc::now())
        .await
        .map_err(|error| {
            AppError::internal(format!("availability idempotency pruning failed: {error}"))
        })?;
    // The preparation signs a service-authored timestamp. Serialize local
    // construction so concurrent byte-identical requests cannot manufacture
    // sibling preparations before the durable first-response row lands.
    let availability_lock = service_event_authoring_lock();
    let _availability_guard = availability_lock.lock().await;
    if let Some(record) = state
        .persistence()
        .scoped_idempotency_record(
            &authenticated_actor,
            "ak.self.seals.command.issue_availability_receipts",
            &idempotency_key,
        )
        .await
        .map_err(|error| {
            AppError::internal(format!("availability idempotency lookup failed: {error}"))
        })?
    {
        if let Some(cached) = availability_idempotency_outcome(record, &request, &request_hash)? {
            return json_ok(cached);
        }
        return json_ok(
            wait_for_availability_idempotency_outcome(
                state,
                &authenticated_actor,
                &idempotency_key,
                &request,
                &request_hash,
            )
            .await?,
        );
    }

    let mut current = state
        .projections()
        .realm_seal_leaves(&request.realm_id)
        .await
        .map_err(|error| AppError::internal(format!("Seal frontier unavailable: {error}")))?;
    current.sort();
    if current != request.predecessor_refs {
        return Err(crate::app_error!(
            FrontierUnavailable,
            "availability preparation predecessor_refs are not the exact current Seal frontier",
        ));
    }
    let predecessor_covered = state
        .projections()
        .predecessor_covered_events(&request.predecessor_refs)
        .await
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    let mut events = Vec::with_capacity(request.event_digests.len());
    for digest in &request.event_digests {
        if predecessor_covered.contains(digest) {
            return Err(crate::app_error!(
                StateMismatch,
                "availability preparation Event is already covered by the predecessor frontier",
            ));
        }
        let event = crate::notary::durable_control_event_by_digest(state, digest)
            .await
            .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
        if event.realm_id != request.realm_id {
            return Err(crate::app_error!(
                StateMismatch,
                "availability preparation contains a cross-Realm Control Event",
            ));
        }
        events.push((digest.clone(), event));
    }
    let predecessor_state = state
        .projections()
        .effective_state_at(&request.predecessor_refs, &request.realm_id)
        .await
        .map_err(|error| crate::app_error!(FrontierUnavailable, error.to_string()))?;
    let digest_suites = state
        .projections()
        .seal_digest_suites_for_delta(
            &request.realm_id,
            &request.predecessor_refs,
            &request.event_digests,
        )
        .await
        .map_err(|error| crate::app_error!(StateMismatch, error.to_string()))?;
    let reservation_at =
        chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis())
            .ok_or_else(|| AppError::internal("availability reservation time is invalid"))?;
    let reservation = soland_storage::IdempotencyRecord {
        authenticated_actor: authenticated_actor.clone(),
        operation_id: "ak.self.seals.command.issue_availability_receipts".to_owned(),
        idempotency_key: idempotency_key.clone(),
        request_hash: request_hash.clone(),
        response_status: AVAILABILITY_RESERVATION_STATUS,
        response_body: serde_json::json!({
            "kind": "availability_preparation_reservation",
            "reservation_id": uuid::Uuid::now_v7(),
        }),
        created_at: reservation_at,
        expires_at: reservation_at + Duration::seconds(AVAILABILITY_RESERVATION_LEASE_SECONDS),
    };
    state
        .persistence()
        .record_idempotency(&reservation)
        .await
        .map_err(|error| {
            AppError::internal(format!("persist availability reservation: {error}"))
        })?;
    let landed_reservation = state
        .persistence()
        .scoped_idempotency_record(
            &authenticated_actor,
            "ak.self.seals.command.issue_availability_receipts",
            &idempotency_key,
        )
        .await
        .map_err(|error| AppError::internal(format!("reload availability reservation: {error}")))?
        .ok_or_else(|| AppError::internal("availability reservation did not persist"))?;
    if landed_reservation != reservation {
        if let Some(cached) =
            availability_idempotency_outcome(landed_reservation, &request, &request_hash)?
        {
            return json_ok(cached);
        }
        return json_ok(
            wait_for_availability_idempotency_outcome(
                state,
                &authenticated_actor,
                &idempotency_key,
                &request,
                &request_hash,
            )
            .await?,
        );
    }
    // AvailabilityReceipt timestamps are canonicalized at millisecond
    // precision. Freeze the preparation time at that same precision so an
    // exact retention boundary cannot lose sub-millisecond time during wire
    // serialization and then fail its own `sealed_at + minimum` check.
    let sealed_at = chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis())
        .ok_or_else(|| AppError::internal("availability sealed_at is outside timestamp range"))?;
    let worker = crate::notary::NotaryWorker::for_service(state.service_id().clone());
    let dependencies = worker
        .issue_availability_dependencies(
            state,
            &request.realm_id,
            &request.predecessor_refs,
            &predecessor_state,
            &predecessor_covered.iter().cloned().collect::<Vec<_>>(),
            &events,
            digest_suites.event_digest_suite,
            sealed_at,
        )
        .await
        .map_err(|error| match error {
            crate::notary::NotaryError::NotAuthorized(message) => {
                crate::app_error!(SealSignerUnauthorized, message)
            }
            other => crate::app_error!(StateMismatch, other.to_string()),
        })?;
    for dependency in &dependencies {
        state
            .persistence()
            .governance_dependency_store()
            .put_realm_object_exact(&request.realm_id, dependency.clone())
            .await
            .map_err(|error| {
                AppError::internal(format!("persist availability dependency: {error}"))
            })?;
    }
    let mut availability_receipt_digests = dependencies
        .iter()
        .filter_map(|dependency| match dependency {
            GovernanceDependency::AvailabilityReceipt {
                selector: GovernanceDependencySelector::AvailabilityReceipt { content_digest },
                ..
            } => Some(content_digest.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    availability_receipt_digests.sort();
    let outcome = SealAvailabilityReceiptIssueOutcome {
        realm_id: request.realm_id.clone(),
        predecessor_refs: request.predecessor_refs.clone(),
        event_digests: request.event_digests.clone(),
        sealed_at,
        availability_receipt_digests,
        governance_dependencies: dependencies,
    };
    outcome.validate_for_request(&request).map_err(|error| {
        AppError::internal(format!(
            "constructed availability outcome is invalid: {error}"
        ))
    })?;
    let expires_at = outcome
        .governance_dependencies
        .iter()
        .filter_map(|dependency| match dependency {
            GovernanceDependency::AvailabilityReceipt {
                availability_receipt,
                ..
            } => Some(availability_receipt.retention_expires_at),
            _ => None,
        })
        .min()
        .unwrap_or(sealed_at + Duration::seconds(IDEMPOTENCY_KEY_TTL_SECONDS));
    let completed = soland_storage::IdempotencyRecord {
        authenticated_actor: authenticated_actor.clone(),
        operation_id: "ak.self.seals.command.issue_availability_receipts".to_owned(),
        idempotency_key: idempotency_key.clone(),
        request_hash: request_hash.clone(),
        response_status: StatusCode::OK.as_u16() as i32,
        response_body: serde_json::to_value(&outcome).map_err(|error| {
            AppError::internal(format!("encode availability idempotency outcome: {error}"))
        })?,
        created_at: sealed_at,
        expires_at,
    };
    let completed_by_owner = state
        .persistence()
        .complete_idempotency_reservation(&reservation, &completed)
        .await
        .map_err(|error| {
            AppError::internal(format!("complete availability reservation: {error}"))
        })?;
    if !completed_by_owner {
        return json_ok(
            wait_for_availability_idempotency_outcome(
                state,
                &authenticated_actor,
                &idempotency_key,
                &request,
                &request_hash,
            )
            .await?,
        );
    }
    let landed = state
        .persistence()
        .scoped_idempotency_record(
            &authenticated_actor,
            "ak.self.seals.command.issue_availability_receipts",
            &idempotency_key,
        )
        .await
        .map_err(|error| {
            AppError::internal(format!("reload availability idempotency outcome: {error}"))
        })?
        .ok_or_else(|| AppError::internal("availability idempotency outcome did not persist"))?;
    let landed =
        availability_idempotency_outcome(landed, &request, &request_hash)?.ok_or_else(|| {
            AppError::internal("availability reservation remained pending after completion")
        })?;
    json_ok(landed)
}

#[salvo::oapi::endpoint(operation_id = "ak.self.seals.command.submit", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.seals.command.submit.v1"))]
async fn submit_event_seal(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<Seal>,
) -> JsonResult<EventSealSubmitOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    super::super::require_agent_session_scope(
        &session,
        arkret_wire::ServiceOperationId::SELF_SEALS_COMMAND_SUBMIT_V1,
    )?;
    let seal = body.into_inner();
    let session_core_id = arkret_wire::DidCoreId::new(session.actor.clone()).map_err(|error| {
        crate::app_error!(
            PolicyViolation,
            format!("Seal submitter DID core id is invalid: {error}"),
        )
    })?;
    let own_pcr = state
        .projections()
        .snapshot()
        .realm_is_principal_control_for_actor(
            seal.realm_id.as_str(),
            &crate::routing::identity::session_actor::session_actor_from_credential(
                state, &session,
            )?
            .to_string(),
        );
    let agent = if own_pcr {
        None
    } else {
        crate::routing::identity::agent_pcr::agent_record_for_controller_pcr(
            state,
            &session.actor,
            seal.realm_id.as_str(),
        )
        .await?
    };
    if !own_pcr && agent.is_none() {
        return Err(crate::app_error!(
            PolicyViolation,
            "Seal submission is limited to the caller's own or delegated Agent principal-control Realm",
        ));
    }
    let NotarySig::Single(signature) = &seal.notary_signature else {
        return Err(crate::app_error!(
            PolicyViolation,
            "principal-control Seal submission requires one bound device signature",
        ));
    };
    if !crate::routing::federation::move_seal::session_device_verification_method_matches(
        session_core_id.as_str(),
        &session.device_id,
        &signature.verification_method,
    ) {
        return Err(crate::app_error!(
            PolicyViolation,
            "Seal signer does not match the authenticated session device",
        ));
    }

    let effect = if let Some(agent_record) = agent.as_ref() {
        crate::routing::federation::move_seal::apply_agent_event_seal(
            state,
            &seal,
            agent_record,
            &session.device_id,
        )
        .await?
    } else {
        crate::routing::federation::move_seal::apply_inbound_seal(state, &seal).await?
    };
    state
        .projections()
        .reload_cells_from_store(&seal.realm_id)
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "refresh projected cells after principal Seal acceptance: {error}"
            ))
        })?;
    // The wire field is a set (byte-wise ascending, unique), the same
    // normalization `Seal.delta` carries. `SealEffect` holds reducer apply order
    // — causal, then digest-descending — which a client cannot reproduce.
    // Serving it raw made this response disagree with the short-circuit paths in
    // `move_seal`, which return `seal.delta`.
    let accepted_event_digests = effect.wire_accepted_event_digests();
    json_ok(EventSealSubmitOutcome {
        seal_id: effect.seal,
        accepted_event_digests,
        post_state_root: effect.post_state_root,
    })
}

#[salvo::oapi::endpoint(operation_id = "ak.self.events.read.describe", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.events.read.describe.v1"))]
async fn events_describe(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<arkret_models_discovery::ServiceDescribe> {
    if req.method().as_str() == "QUERY" {
        req.parse_json::<arkret_models_collaboration::event_query::EventsDescribeRequestBody>()
            .await
            .map_err(|_| {
                AppError::json_invalid("invalid ak.self.events.read.describe.v1 request body")
            })?;
    }
    let state = depot.get_typed::<AppState>().expect("state injected");
    let mut description = describe(
        state.service_resolution_commitment().as_ref(),
        state.jobs().storage_mode(),
        state.config(),
    );
    crate::routing::events::sync::websocket::advertise_websocket_binding(state, &mut description);
    crate::routing::system::describe::apply_claim_level_partition(
        &mut description,
        state.verified_profiles(),
    );
    // Advertise the live rate-limit ceilings (see the canonical describe
    // handler) so wire and enforcement stay in lock-step after a hot-swap.
    description.rate_limit_policy = Some(
        state
            .settings()
            .rate_limit
            .to_limiter_config()
            .advertised_policy(),
    );
    {
        let limits = &mut description.limits.extensions;
        limits.insert(
            "max_event_bytes".to_owned(),
            json!(MAX_EVENT_ENVELOPE_BYTES),
        );
        limits.insert("max_prev_refs".to_owned(), json!(MAX_EVENT_PREV_REFS));
        limits.insert("max_refs".to_owned(), json!(MAX_EVENT_REFS));
        limits.insert(
            "max_batch_item_count".to_owned(),
            json!(MAX_EVENT_SUBMIT_BATCH),
        );
        limits.insert("max_resolve".to_owned(), json!(MAX_EVENT_RESOLVE));
        limits.insert("max_list_limit".to_owned(), json!(100));
    }
    json_ok(description)
}

#[salvo::oapi::endpoint(operation_id = "ak.self.events.command.submit", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.events.command.submit.v1"))]
async fn submit_event(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.get_typed::<AppState>().expect("state injected");
    // api-conventions.md §6 — read the generic `Idempotency-Key` header before
    // the body is consumed; an empty / blank value is treated as absent so a
    // misconfigured client does not collapse every write onto one key.
    let idempotency_key = req
        .headers()
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let submit = match req.parse_json::<SolandEventsSubmitRequestBody>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "json_invalid",
                "invalid event envelope",
            );
            return;
        }
    };
    if matches!(submit, SolandEventsSubmitRequestBody::Federation(_)) {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "federation peer event submission uses /_arkret/peer/events",
        );
        return;
    }
    if matches!(
        submit,
        SolandEventsSubmitRequestBody::DirectConversationFounding(_)
    ) && idempotency_key.is_some()
    {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "Direct Conversation founding carries idempotency_key only in its body",
        );
        return;
    }
    let Some(session) = auth_or_render(state, req, res).await else {
        return;
    };
    if let Err(error) = super::super::require_agent_session_scope(
        &session,
        arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
    ) {
        render_error(res, error.http_status(), error.wire_code(), &error.message);
        return;
    }

    submit_event_authenticated(state, &session, idempotency_key, submit, res).await;
}

fn submit_event_authenticated<'a>(
    state: &'a AppState,
    session: &'a SessionRecord,
    idempotency_key: Option<String>,
    submit: SolandEventsSubmitRequestBody,
    res: &'a mut Response,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
    Box::pin(async move {
        // §6 generic idempotency key path. When present, the key is scoped to the
        // authenticated principal: a replay carrying the SAME canonical body
        // returns the cached first response; the SAME key with a DIFFERENT
        // canonical body is a `duplicate_conflict`. Event-ID idempotency below
        // still applies independently (a write with no header relies on it).
        if let Some(key) = idempotency_key.as_deref() {
            let request_hash = match arkret_canonical::canonical_sha256(&submit) {
                Ok(hash) => hash,
                Err(error) => {
                    render_error(
                        res,
                        StatusCode::BAD_REQUEST,
                        "schema_violation",
                        &format!("request body is not canonical-hashable: {error}"),
                    );
                    return;
                }
            };
            let authenticated_actor =
                match crate::routing::identity::session_actor::session_actor_from_credential(
                    state, session,
                ) {
                    Ok(actor) => actor,
                    Err(error) => {
                        render_error(res, error.http_status(), error.wire_code(), &error.message);
                        return;
                    }
                };
            match state
                .jobs()
                .scoped_idempotency_record(
                    &authenticated_actor,
                    "ak.self.events.command.submit.v1",
                    key,
                )
                .await
            {
                Ok(Some(record)) if record.request_hash == request_hash => {
                    // Replay: re-emit the cached first response verbatim, no
                    // re-execution and no second side effect.
                    let status = StatusCode::from_u16(record.response_status as u16)
                        .unwrap_or(StatusCode::OK);
                    res.status_code(status);
                    res.render(Json(record.response_body));
                    return;
                }
                Ok(Some(_)) => {
                    render_error(
                        res,
                        StatusCode::CONFLICT,
                        "duplicate_conflict",
                        "Idempotency-Key was reused with a different request body",
                    );
                    return;
                }
                Ok(None) => {}
                Err(error) => {
                    render_error(
                        res,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        &format!("idempotency lookup failed: {error}"),
                    );
                    return;
                }
            }
            let (status, body, idempotency_committed) = match submit {
                SolandEventsSubmitRequestBody::Single(envelope) => {
                    let envelope_for_chaos = envelope.clone();
                    let result = submit_event_value_with_idempotency(
                        state,
                        session,
                        envelope,
                        EventCommitIdempotency {
                            authenticated_actor: authenticated_actor.clone(),
                            operation_id: "ak.self.events.command.submit.v1".to_owned(),
                            key: key.to_owned(),
                            request_hash: request_hash.clone(),
                        },
                    )
                    .await;
                    match result {
                        Ok(response) => {
                            maybe_delay_test_chaos_breakpoint(
                                state,
                                &envelope_for_chaos,
                                &response,
                            )
                            .await;
                            let committed = !response.duplicate;
                            (
                                StatusCode::OK,
                                submit_outcome_value(&response.outcome),
                                committed,
                            )
                        }
                        Err(error) => {
                            let (status, body) = submit_one_error_value(error);
                            (status, body, false)
                        }
                    }
                }
                other => {
                    let (status, body) = submit_event_dispatch(state, session, other).await;
                    (status, body, false)
                }
            };
            // Only deterministic outcomes are cached: a 5xx is transient, so caching
            // it would wrongly pin a server-side failure under the key and block a
            // legitimate retry. The client may safely re-send the same key.
            if !status.is_server_error() && !idempotency_committed {
                persist_idempotency_first_response(
                    state,
                    &authenticated_actor,
                    key,
                    &request_hash,
                    status,
                    &body,
                )
                .await;
            }
            res.status_code(status);
            if status.is_client_error() || status.is_server_error() {
                res.headers_mut().insert(
                    salvo::http::header::CONTENT_TYPE,
                    salvo::http::HeaderValue::from_static("application/problem+json"),
                );
            }
            res.render(Json(body));
            return;
        }

        match submit {
            SolandEventsSubmitRequestBody::Federation(_) => unreachable!("handled before auth"),
            SolandEventsSubmitRequestBody::AgentMembershipCascade(submission) => {
                match submit_agent_membership_cascade(state, session, submission).await {
                    Ok(outcome) => res.render(Json(outcome)),
                    Err(error) => render_submit_one_error(res, error),
                }
            }
            SolandEventsSubmitRequestBody::DirectConversationFounding(submission) => {
                match submit_direct_conversation_founding_unit(state, session, submission).await {
                    Ok(outcome) => res.render(Json(outcome)),
                    Err(error) => render_submit_one_error(res, error),
                }
            }
            SolandEventsSubmitRequestBody::Initial(submission) => {
                match submit_initial_event_submission(state, session, submission).await {
                    Ok(response) => res.render(Json(response.outcome)),
                    Err(error) => render_submit_one_error(res, error),
                }
            }
            SolandEventsSubmitRequestBody::InitialBatch(batch) => {
                match submit_initial_event_batch_outcome(state, session, batch.events).await {
                    Ok(outcome) => res.render(Json(outcome)),
                    Err(error) => render_submit_one_error(res, error),
                }
            }
            SolandEventsSubmitRequestBody::Single(envelope) => {
                let envelope_for_chaos = envelope.clone();
                match submit_event_value(state, session, envelope).await {
                    Ok(response) => {
                        maybe_delay_test_chaos_breakpoint(state, &envelope_for_chaos, &response)
                            .await;
                        res.render(Json(response.outcome));
                    }
                    Err(error) => render_submit_one_error(res, error),
                }
            }
        }
    })
}

/// How long a generic `Idempotency-Key` mapping is retained. api-conventions.md
/// §6 only requires "at least until the related Event is fully synced or
/// expired"; 24h comfortably covers a client's retry horizon while keeping the
/// table bounded under the periodic TTL sweep.
/// Run the (already-authenticated, non-federation) submit and reduce it to the
/// rendered `(status, body)` pair — the same value either rendered directly or
/// cached under an `Idempotency-Key`. Mirrors the no-key match arms exactly so
/// the cached first response is byte-for-byte what a keyless write would emit.
async fn submit_event_dispatch(
    state: &AppState,
    session: &SessionRecord,
    submit: SolandEventsSubmitRequestBody,
) -> (StatusCode, Value) {
    match submit {
        SolandEventsSubmitRequestBody::Federation(_) => unreachable!("handled before auth"),
        SolandEventsSubmitRequestBody::AgentMembershipCascade(submission) => {
            match submit_agent_membership_cascade(state, session, submission).await {
                Ok(outcome) => (StatusCode::OK, submit_outcome_value(&outcome)),
                Err(error) => submit_one_error_value(error),
            }
        }
        SolandEventsSubmitRequestBody::DirectConversationFounding(submission) => {
            match submit_direct_conversation_founding_unit(state, session, submission).await {
                Ok(outcome) => (
                    StatusCode::OK,
                    serde_json::to_value(outcome)
                        .unwrap_or_else(|_| json!({"unit_kind":"direct_conversation_founding"})),
                ),
                Err(error) => submit_one_error_value(error),
            }
        }
        SolandEventsSubmitRequestBody::Initial(submission) => {
            match submit_initial_event_submission(state, session, submission).await {
                Ok(response) => (StatusCode::OK, submit_outcome_value(&response.outcome)),
                Err(error) => submit_one_error_value(error),
            }
        }
        SolandEventsSubmitRequestBody::InitialBatch(batch) => {
            match submit_initial_event_batch_outcome(state, session, batch.events).await {
                Ok(outcome) => (StatusCode::OK, submit_outcome_value(&outcome)),
                Err(error) => submit_one_error_value(error),
            }
        }
        SolandEventsSubmitRequestBody::Single(envelope) => {
            let envelope_for_chaos = envelope.clone();
            match submit_event_value(state, session, envelope).await {
                Ok(response) => {
                    maybe_delay_test_chaos_breakpoint(state, &envelope_for_chaos, &response).await;
                    (StatusCode::OK, submit_outcome_value(&response.outcome))
                }
                Err(error) => submit_one_error_value(error),
            }
        }
    }
}

fn submit_outcome_value(
    outcome: &arkret_models_collaboration::http_bodies::EventsSubmitOutcome,
) -> Value {
    serde_json::to_value(outcome).unwrap_or_else(|_| json!({"status": "accepted"}))
}

/// Render a `SubmitOneError` to the same `(status, body)` shape
/// `render_submit_one_error` writes: a quarantine error becomes a 200 `partial`
/// outcome, every other error becomes the standard error envelope.
fn submit_one_error_value(error: SubmitOneError) -> (StatusCode, Value) {
    if let SubmitOneError::Quarantined { event_id, .. } = error {
        let outcome = events_submit_outcome(
            arkret_models_collaboration::http_bodies::EventsSubmitStatus::Partial,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![event_id],
            None,
        );
        return (StatusCode::OK, submit_outcome_value(&outcome));
    }
    let SubmitOneError::Rejected { error, details } = error else {
        unreachable!();
    };
    let mut body = json!(
        arkret_wire::problem_details::ErrorEnvelope::new(
            error.wire_code(),
            error.message.as_ref(),
        )
            .with_request_id(crate::ids::generate_request_id())
    );
    if let Some(details) = details.as_ref().and_then(Value::as_object)
        && let Some(problem) = body.as_object_mut()
    {
        problem.extend(details.clone());
    }
    (error.http_status(), body)
}

/// Persist the FIRST response under an `Idempotency-Key`. Best-effort: a failed
/// write is downgraded to a warning rather than failing the request the caller
/// already executed — a missing mapping only costs a later replay its cache hit
/// (it re-executes, and Event-ID idempotency still de-duplicates the work).
async fn persist_idempotency_first_response(
    state: &AppState,
    authenticated_actor: &arkret_wire::ActorId,
    idempotency_key: &str,
    request_hash: &str,
    status: StatusCode,
    body: &Value,
) {
    let created_at = now();
    let record = soland_services::jobs::IdempotencyState {
        authenticated_actor: authenticated_actor.clone(),
        operation_id: "ak.self.events.command.submit.v1".to_owned(),
        idempotency_key: idempotency_key.to_owned(),
        request_hash: request_hash.to_owned(),
        response_status: status.as_u16() as i32,
        response_body: body.clone(),
        created_at,
        expires_at: created_at + Duration::seconds(IDEMPOTENCY_KEY_TTL_SECONDS),
    };
    if let Err(error) = state.jobs().store_idempotency_record(record).await {
        tracing::warn!(%error, idempotency_key, "idempotency first-response persist failed");
    }
}

async fn maybe_delay_test_chaos_breakpoint(
    state: &AppState,
    envelope: &Value,
    response: &SubmittedEventOutcome,
) {
    let operation_id = envelope_operation_id(envelope);
    crate::routing::events::test_chaos::maybe_delay_before_event_response(
        state,
        operation_id.as_deref(),
        &response.event_id,
    )
    .await;
}

fn envelope_operation_id(envelope: &Value) -> Option<String> {
    envelope
        .get("unsigned")
        .and_then(Value::as_object)
        .and_then(|unsigned| unsigned.get("local_operation_idempotency_alias"))
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("ak:operation:"))
        .map(ToOwned::to_owned)
}

#[salvo::oapi::endpoint(operation_id = "ak.self.events.resource.get", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.events.resource.get.v1"))]
async fn get_event(
    aa: AuthArgs,
    event_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<EventView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let event_id = event_id.into_inner();
    let record = state
        .event_queries()
        .canonical_event(&event_id)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| AppError::not_found("event not found"))?;
    if !event_visible_to_session(state, &record, &session).await {
        return Err(AppError::not_found("event not found"));
    }
    event_view_for_state(state, &record).await
}

#[salvo::oapi::endpoint(operation_id = "ak.self.events.read.delivery_status", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.events.read.delivery_status.v1"))]
async fn event_delivery_status(
    aa: AuthArgs,
    body: JsonBody<EventDeliveryStatusRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<EventDeliveryStatusOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    super::super::require_agent_session_scope(
        &session,
        arkret_wire::ServiceOperationId::SELF_EVENTS_READ_DELIVERY_STATUS_V1,
    )?;
    let body = body.into_inner();
    let event_id = body.event_id.as_str();
    let record = state
        .event_queries()
        .canonical_event(event_id)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| AppError::not_found("event not found"))?;
    if !event_visible_to_session(state, &record, &session).await {
        return Err(AppError::not_found("event not found"));
    }
    let deliveries = state
        .federation()
        .deliveries_for_event(event_id)
        .await
        .map_err(|error| {
            AppError::internal(format!("Event delivery status unavailable: {error}"))
        })?;
    let mut targets = BTreeMap::new();
    for delivery in deliveries {
        let Some(binding) = delivery.delivery.realm_fanout.as_ref() else {
            continue;
        };
        if !binding
            .source_event_ids
            .iter()
            .any(|source| source == event_id)
        {
            continue;
        }
        let status = match delivery.state {
            soland_storage::FederationOutboxState::PendingRoute => {
                EventDeliveryTargetState::PendingRoute
            }
            soland_storage::FederationOutboxState::Pending => {
                EventDeliveryTargetState::PendingDelivery
            }
            soland_storage::FederationOutboxState::Leased => {
                if delivery.leased_from_state
                    == Some(soland_storage::FederationOutboxState::PendingRoute)
                {
                    EventDeliveryTargetState::PendingRoute
                } else {
                    EventDeliveryTargetState::PendingDelivery
                }
            }
            soland_storage::FederationOutboxState::Delivered => EventDeliveryTargetState::Delivered,
            soland_storage::FederationOutboxState::CancelledAuthorityLost => {
                EventDeliveryTargetState::CancelledAuthorityLost
            }
            soland_storage::FederationOutboxState::PolicySuppressed
            | soland_storage::FederationOutboxState::DeadLettered
            | soland_storage::FederationOutboxState::Superseded => {
                return Err(AppError::internal(
                    "Realm fanout row entered a state forbidden by the delivery-status contract",
                ));
            }
        };
        let target_id = delivery.delivery.id.clone();
        let can_read_service_id = caller_can_read_delivery_target_service(
            state,
            &session,
            binding,
            delivery.delivery.peer_id.as_str(),
        )
        .await;
        let service_id = can_read_service_id.then(|| delivery.delivery.peer_id.clone());
        let target = EventDeliveryTargetStatus {
            target_id: target_id.clone(),
            status,
            service_id,
        };
        if targets.insert(target_id, target).is_some() {
            return Err(AppError::internal(
                "duplicate durable Realm fanout target for one Event",
            ));
        }
    }
    let targets = targets.into_values().collect::<Vec<_>>();
    let outcome = EventDeliveryStatusOutcome {
        event_id: body.event_id,
        targets,
    };
    outcome
        .validate()
        .map_err(|error| AppError::internal(format!("invalid Event delivery status: {error}")))?;
    json_ok(outcome)
}

async fn caller_can_read_delivery_target_service(
    state: &AppState,
    session: &SessionRecord,
    binding: &soland_services::federation::RealmFanoutBinding,
    recipient_id: &str,
) -> bool {
    for witness in &binding.authority_witnesses {
        let member_key = witness.member_id.to_string();
        let witness_is_current = state
            .projections()
            .snapshot()
            .member(&binding.realm_id, &member_key)
            .is_some_and(|member| {
                member.state == "join"
                    && witness.member_id.route_service_id().as_str() == recipient_id
                    && member.membership_event_ref.as_deref()
                        == Some(witness.membership_event_ref.as_str())
            });
        if !witness_is_current {
            continue;
        }
        let Ok(Some(membership_event)) = state
            .event_queries()
            .canonical_event(&witness.membership_event_ref)
            .await
        else {
            continue;
        };
        if !event_visible_to_session(state, &membership_event, session).await {
            continue;
        }
        return true;
    }
    false
}

async fn verified_contact_mirror_event(
    state: &AppState,
    session: &SessionRecord,
    mirror: soland_storage::ContactVerifiedMirrorRecord,
) -> Result<Option<(Event, Hash)>, AppError> {
    let event: Event = serde_json::from_slice(&mirror.canonical_event_bytes)
        .map_err(|error| AppError::internal(format!("Contact mirror Event decode: {error}")))?;
    let request_digest = Hash::new(mirror.request_digest.clone())
        .map_err(|error| AppError::internal(format!("Contact mirror digest invalid: {error}")))?;
    let digest_suite = request_digest
        .digest_suite()
        .map_err(|error| AppError::internal(format!("Contact mirror digest suite: {error}")))?;
    if canonical::canonical_json_bytes(&event).map_err(|error| {
        AppError::internal(format!("Contact mirror Event canonicalize: {error}"))
    })? != mirror.canonical_event_bytes
        || event.kind != arkret_wire::EventKind::ContactRequested
        || event.event_id.as_str() != mirror.request_event_id
        || event
            .event_digest_with_digest_suite(digest_suite)
            .map_err(|error| AppError::internal(format!("Contact mirror Event digest: {error}")))?
            != mirror.request_digest
        || mirror.target_holder_principal_id != session.actor
    {
        return Ok(None);
    }
    let payload = serde_json::from_value::<ContactRequestedPayload>(
        serde_json::to_value(&event.payload).map_err(|error| {
            AppError::internal(format!("Contact mirror payload encode: {error}"))
        })?,
    )
    .map_err(|error| AppError::internal(format!("Contact mirror payload decode: {error}")))?;
    let session_actor_id =
        crate::routing::identity::session_actor::session_actor_from_credential(state, session)?;
    if payload.peer.contact_actor_id() != session_actor_id {
        return Ok(None);
    }
    let Ok(Some(contact)) = state
        .contacts()
        .contact_any(&event.actor_id, &session_actor_id)
        .await
    else {
        return Ok(None);
    };
    if contact.status != "pending"
        || contact.requester_id != event.actor_id
        || contact.target_id != session_actor_id
        || contact.request_event_ref.as_ref() != Some(&event.event_id)
        || contact.peer_host_id.as_ref().map(|id| id.as_str()) != Some(mirror.issuer_id.as_str())
    {
        return Ok(None);
    }
    let receipt_matches = contact.request_receipts.iter().any(|receipt| {
        receipt.core.holder.contact_actor_id() == event.actor_id
            && receipt.core.peer.contact_actor_id() == session_actor_id
            && receipt.core.request_event_ref == event.event_id
            && receipt.core.request_digest().as_str() == mirror.request_digest
            && receipt == &mirror.source_receipt
    });
    if !receipt_matches {
        return Ok(None);
    }
    Ok(Some((event, request_digest)))
}

#[salvo::oapi::endpoint(operation_id = "ak.self.events.read.resolve", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.events.read.resolve.v1"))]
async fn resolve_events(
    aa: AuthArgs,
    body: JsonBody<EventsResolveRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<EventsResolveOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    body.validate()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    if body.history_traversal_access.is_some() && body.include_payload == Some(false) {
        return Err(AppError::param_invalid(
            "history traversal requires the complete accepted Event payload",
        ));
    }
    if body.event_ids.len() + body.event_digests.len() > MAX_EVENT_RESOLVE {
        return Err(crate::app_error!(
            LimitExceeded,
            "too many events requested",
        ));
    }
    if let Some(access) = body.history_traversal_access.clone() {
        let caller = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(session.actor.clone()).map_err(|error| {
                AppError::internal(format!("session actor is invalid: {error}"))
            })?,
            state.service_core_id().clone(),
        ));
        let retained = state
            .persistence()
            .governance_history_service()
            .resolve_self_retained_events_for_access(access, &caller, now())
            .await
            .map_err(|error| AppError::internal(format!("history traversal access: {error}")))?;
        let mut found = Vec::new();
        let mut missing = Vec::new();
        for event_id in &body.event_ids {
            match retained.iter().find(|event| event.event_id == *event_id) {
                Some(event) => found.push(event.clone()),
                None => missing.push(event_id.to_string()),
            }
        }
        for digest in &body.event_digests {
            let event = retained.iter().find(|event| {
                arkret::signed_event_digest_claim(event).is_ok_and(|retained_digest| {
                    retained_digest == *digest
                        && retained_digest.digest_suite().is_ok_and(|digest_suite| {
                            event
                                .event_digest_with_digest_suite(digest_suite)
                                .is_ok_and(|actual| actual == digest.as_str())
                        })
                })
            });
            match event {
                Some(event)
                    if !found.iter().any(|found_event: &arkret_wire::Event| {
                        found_event.event_id == event.event_id
                    }) =>
                {
                    found.push(event.clone());
                }
                Some(_) => {}
                None => missing.push(digest.to_string()),
            }
        }
        let outcome = EventsResolveOutcome {
            events: found,
            missing,
            unauthorized: Vec::new(),
        };
        let encoded = arkret_canonical::canonical_json_bytes(&outcome)
            .map_err(|error| AppError::internal(format!("events resolve outcome: {error}")))?;
        let byte_limit = body.max_response_bytes.unwrap_or(8 * 1024 * 1024) as usize;
        if encoded.len() > byte_limit {
            return Err(crate::app_error!(
                LimitExceeded,
                "events resolve outcome exceeds max_response_bytes",
            ));
        }
        return json_ok(outcome);
    }
    let service = state.event_queries();
    let mut found = Vec::new();
    let mut missing = Vec::new();
    let include_payload = body.include_payload.unwrap_or(true);
    for event_id in &body.event_ids {
        let event_id_string = event_id.to_string();
        if let Some(mirror) = state
            .persistence()
            .contact_verified_mirror(&session.actor, &event_id_string)
            .await
            .map_err(|error| {
                AppError::internal(format!("events resolve Contact mirror: {error}"))
            })?
            && let Some((event, _digest)) =
                verified_contact_mirror_event(state, &session, mirror).await?
        {
            found.push(event);
            continue;
        }
        match service
            .canonical_event(&event_id_string)
            .await
            .ok()
            .flatten()
        {
            Some(record) if event_visible_to_session(state, &record, &session).await => {
                let mut event = sdk_event_for_state(state, &record)?;
                if !include_payload {
                    event.payload.clear();
                }
                found.push(event);
            }
            _ => missing.push(event_id_string),
        }
    }
    if !body.event_digests.is_empty() {
        let records = service
            .canonical_events()
            .await
            .map_err(|error| AppError::internal(format!("events resolve: {error}")))?;
        for digest in &body.event_digests {
            if let Some(mirror) = state
                .persistence()
                .contact_verified_mirror_by_digest(&session.actor, digest.as_str())
                .await
                .map_err(|error| {
                    AppError::internal(format!("events resolve Contact mirror: {error}"))
                })?
                && let Some((event, _canonical_digest)) =
                    verified_contact_mirror_event(state, &session, mirror).await?
            {
                if !found
                    .iter()
                    .any(|found_event| found_event.event_id == event.event_id)
                {
                    found.push(event);
                }
                continue;
            }
            let Some(record) = records
                .iter()
                .find(|record| record.canonical_digest == digest.as_str())
            else {
                missing.push(digest.to_string());
                continue;
            };
            if !event_visible_to_session(state, record, &session).await {
                missing.push(digest.to_string());
                continue;
            }
            if !found
                .iter()
                .any(|event| event.event_id.as_str() == record.event_id)
            {
                let mut event = sdk_event_for_state(state, record)?;
                if !include_payload {
                    event.payload.clear();
                }
                found.push(event);
            }
        }
    }
    let outcome = EventsResolveOutcome {
        events: found,
        missing,
        unauthorized: Vec::new(),
    };
    let encoded = arkret_canonical::canonical_json_bytes(&outcome)
        .map_err(|error| AppError::internal(format!("events resolve outcome: {error}")))?;
    let byte_limit = body.max_response_bytes.unwrap_or(8 * 1024 * 1024) as usize;
    if encoded.len() > byte_limit {
        return Err(crate::app_error!(
            LimitExceeded,
            "events resolve outcome exceeds max_response_bytes",
        ));
    }
    json_ok(outcome)
}

#[salvo::oapi::endpoint(operation_id = "ak.self.seals.read.frontier", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.seals.read.frontier.v1"))]
async fn seals_frontier(
    aa: crate::routing::system::extract::AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> soland_http::result::JsonResult<SealFrontierState> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let session_actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?;
    let query_body = req
        .parse_json::<arkret_models_collaboration::event_query::SealFrontierRequestBody>()
        .await
        .map_err(|_| {
            AppError::json_invalid("invalid ak.self.seals.read.frontier.v1 request body")
        })?;
    let realm_id = query_body.realm_id;
    let own_pcr = state
        .projections()
        .snapshot()
        .realm_is_principal_control_for_actor(realm_id.as_str(), &session_actor.to_string());
    let agent_pcr = crate::routing::identity::agent_pcr::controller_manages_agent_pcr(
        state,
        &session.actor,
        realm_id.as_str(),
    )
    .await?;
    let accessible = own_pcr
        || agent_pcr
        || crate::routing::spaces::space::realm_id_accessible(
            state,
            realm_id.as_str(),
            Some(&session),
        )
        .await;
    if !accessible {
        // Same code as invisible-event reads: existence must not leak.
        return Err(AppError::not_found("realm not found"));
    }
    if agent_pcr {
        // Agent PCR Seals are device-generation artifacts. When
        // accepted Events are ahead of the accepted Seal, return the previous
        // signed head so the delegated controller can author the successor;
        // the service must not synthesize that Seal.
        let Some(seal) =
            crate::routing::identity::agent_pcr::agent_event_seal_head(state, realm_id.as_str())
                .await?
        else {
            return Err(crate::app_error!(
                FrontierUnavailable,
                "Agent PCR has no accepted device-signed Seal",
            ));
        };
        let governance_policy =
            crate::control_proposal::control_proposal_policy(state, &realm_id, &[])
                .await
                .map_err(|error| {
                    AppError::internal(format!("control governance policy unavailable: {error}"))
                })?;
        let observation_coordinate =
            realm_seal_frontier_observation_coordinate(state, &realm_id).await?;
        let frontier = RealmSealFrontierView::new(
            realm_id,
            arkret_wire::SealBasis {
                leaves: vec![seal.id.clone()],
            },
            state
                .projections()
                .control_governance_health(&seal.realm_id, chrono::Utc::now(), governance_policy)
                .await
                .map_err(|error| {
                    AppError::internal(format!("control governance health unavailable: {error}"))
                })?,
            observation_coordinate,
        );
        return soland_http::result::json_ok(SealFrontierState {
            frontier,
            receipts: vec![AgentPcrSealHeadReceipt {
                kind: AgentPcrSealHeadReceiptKind::AgentPcrSealHeadV1,
                seal,
            }],
        });
    }
    soland_http::result::json_ok(SealFrontierState {
        frontier: load_realm_seal_frontier(state, &realm_id).await?,
        receipts: Vec::new(),
    })
}

#[salvo::oapi::endpoint(operation_id = "ak.self.events.read.frontier", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.events.read.frontier.v1"))]
async fn events_frontier(
    aa: crate::routing::system::extract::AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> soland_http::result::JsonResult<EventsFrontierState> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let session_actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?;
    let query_body = req
        .parse_json::<arkret_models_collaboration::event_query::EventsFrontierRequestBody>()
        .await
        .map_err(|_| {
            AppError::json_invalid("invalid ak.self.events.read.frontier.v1 request body")
        })?;
    let selected_actor_id = query_body.actor_id.clone();
    let is_session_actor = selected_actor_id == session_actor;
    let is_local_account = selected_actor_id
        .as_account_id()
        .is_some_and(|account| account.station_id == state.service_core_id());
    let actor_id = query_body
        .actor_id
        .signing_principal_id()
        .as_str()
        .to_owned();
    let realm_selector = query_body
        .realm_id
        .as_ref()
        .map(|realm_id| realm_id.as_str().to_owned());

    // Actor selectors are split deliberately: combined Realm+actor is the
    // only authoring surface; actor-only is a read-only per-Realm aggregate.
    let actor = selected_actor_id.to_string();
    let actor_id = arkret_wire::DidCoreId::new(actor_id)
        .map_err(|_| AppError::param_invalid("actor_id must be a valid core identity"))?;
    if let Some(realm_value) = realm_selector {
        let realm_id = RealmId::new(realm_value.clone())
            .map_err(|_| AppError::param_invalid("invalid realm_id"))?;
        let own_actor_pcr = is_session_actor
            && state
                .projections()
                .snapshot()
                .realm_is_principal_control_for_actor(&realm_value, &actor);
        let agent_pcr = state
            .agent_pairings()
            .agent(actor_id.as_str())
            .await
            .map_err(|error| AppError::internal(format!("Agent lookup failed: {error}")))?
            .is_some_and(|record| {
                is_local_account
                    && record.controller_principal_id == session.actor
                    && record.state != AgentLifecycleState::Deactivated
                    && record.principal_control_realm_id == realm_value
            });
        let applet_managed_access =
            applet_managed_actor_pcr_access(state, actor_id.as_str(), &session.actor).await?;
        let applet_managed_actor_pcr = applet_managed_access.as_ref().is_some_and(|access| {
            is_local_account && access.active && access.pcr_realm_id == realm_value
        });
        if applet_managed_access
            .as_ref()
            .is_some_and(|access| access.pcr_realm_id == realm_value && !access.active)
        {
            return Err(AppError::not_found("realm not found"));
        }
        let invited_actor = is_session_actor
            && crate::routing::spaces::space::realm_member_invited_or_joined_at(
                state,
                realm_id.as_str(),
                &actor,
            )
            .await
            .is_some();
        // The combined Realm+actor selector is the authoring surface. A
        // caller must be able to recover its own already-established actor
        // chain even when the discardable Realm directory/membership mirror
        // is not yet rebuilt (notably immediately after an atomic bootstrap
        // commit). This does not synthesize an empty frontier: an unknown
        // Realm still has no canonical records and therefore remains 404.
        let authored_realm_history = if is_session_actor {
            !state
                .event_queries()
                .canonical_events_for_realm_actor(realm_id.as_str(), &actor)
                .await
                .map_err(|error| {
                    AppError::internal(format!("actor frontier unavailable: {error}"))
                })?
                .is_empty()
        } else {
            false
        };
        if !own_actor_pcr
            && !agent_pcr
            && !applet_managed_actor_pcr
            && !invited_actor
            && !authored_realm_history
            && !crate::routing::spaces::space::realm_id_accessible(
                state,
                realm_id.as_str(),
                Some(&session),
            )
            .await
        {
            return Err(AppError::not_found("realm not found"));
        }
        let frontier =
            load_realm_actor_frontier(state, realm_id, selected_actor_id.clone()).await?;
        return soland_http::result::json_ok(EventsFrontierState {
            frontier: EventsFrontierView::RealmActor(frontier),
        });
    }

    let agent_pcr = state
        .agent_pairings()
        .agent(actor_id.as_str())
        .await
        .map_err(|error| AppError::internal(format!("Agent lookup failed: {error}")))?
        .filter(|record| {
            is_local_account
                && record.controller_principal_id == session.actor
                && record.state != AgentLifecycleState::Deactivated
        })
        .map(|record| record.principal_control_realm_id);
    // Applet-managed principals are not Agents. Their immutable
    // provision/PCR anchors live in the Applet record and are visible only to
    // the exact registration service. Revocation keeps historical reads
    // available while the combined selector above refuses authoring access.
    let applet_managed_access =
        applet_managed_actor_pcr_access(state, actor_id.as_str(), &session.actor).await?;
    let applet_managed_actor_pcr = applet_managed_access
        .as_ref()
        .filter(|access| is_local_account && access.owned_by_session)
        .map(|access| access.pcr_realm_id.as_str());
    let own_actor_pcr =
        if is_session_actor && let Some(session_account) = session_actor.as_account_id() {
            state
                .persistence()
                .principal_resolution_by_account_id(session_account)
                .await
                .map_err(|error| {
                    AppError::internal(format!("principal resolution lookup failed: {error}"))
                })?
                .map(|resolution| resolution.pcr_realm_id.to_string())
        } else {
            None
        };
    let records = state
        .event_queries()
        .canonical_events_for_actor(&actor)
        .await
        .map_err(|error| AppError::internal(format!("actor frontier unavailable: {error}")))?;
    let mut realm_ids = records
        .iter()
        .filter_map(|record| record.realm_id.clone())
        .collect::<Vec<_>>();
    realm_ids.sort();
    realm_ids.dedup();
    let mut realms = Vec::new();
    for realm_value in realm_ids {
        let is_applet_pcr = applet_managed_access
            .as_ref()
            .is_some_and(|access| access.pcr_realm_id == realm_value);
        let visible = if is_applet_pcr {
            applet_managed_actor_pcr == Some(realm_value.as_str())
        } else {
            own_actor_pcr.as_deref() == Some(realm_value.as_str())
                || agent_pcr.as_deref() == Some(realm_value.as_str())
                || crate::routing::spaces::space::realm_id_accessible(
                    state,
                    &realm_value,
                    Some(&session),
                )
                .await
        };
        if !visible {
            continue;
        }
        let realm_id = RealmId::new(realm_value)
            .map_err(|_| AppError::internal("stored realm_id is invalid"))?;
        realms.push(load_realm_actor_frontier(state, realm_id, selected_actor_id.clone()).await?);
    }
    let aggregate = ActorAggregateFrontierView {
        kind: ActorAggregateFrontierKind::ActorAggregate,
        actor_id: selected_actor_id,
        frontiers: realms,
    };
    aggregate
        .validate()
        .map_err(|error| AppError::internal(format!("actor aggregate is invalid: {error}")))?;
    soland_http::result::json_ok(EventsFrontierState {
        frontier: EventsFrontierView::ActorAggregate(aggregate),
    })
}

struct AppletManagedActorPcrAccess {
    pcr_realm_id: String,
    owned_by_session: bool,
    active: bool,
    globally_fenced: bool,
}

fn merge_applet_managed_actor_pcr_access(
    access: &mut Option<AppletManagedActorPcrAccess>,
    pcr_realm_id: String,
    owned_by_session: bool,
    installation_live: bool,
    scope_authority_active: bool,
    globally_fenced: bool,
) -> Result<(), AppError> {
    let candidate = access.get_or_insert_with(|| AppletManagedActorPcrAccess {
        pcr_realm_id: pcr_realm_id.clone(),
        owned_by_session: false,
        active: false,
        globally_fenced: false,
    });
    if candidate.pcr_realm_id != pcr_realm_id {
        return Err(AppError::internal(
            "Applet-managed actor installations disagree on the immutable PCR anchor",
        ));
    }
    candidate.owned_by_session |= owned_by_session;
    candidate.active |= owned_by_session && installation_live && scope_authority_active;
    candidate.globally_fenced |= globally_fenced;
    if candidate.globally_fenced {
        candidate.active = false;
    }
    Ok(())
}

/// Resolve an Applet-managed principal through its immutable provision/PCR
/// anchor without pretending it is an Agent. The exact registration
/// service is the only caller allowed to observe the actor's PCR aggregate.
/// A revoked record remains readable for historical recovery, but `active`
/// becomes false so the Realm+actor authoring selector fails closed.
async fn applet_managed_actor_pcr_access(
    state: &AppState,
    actor_id: &str,
    session_service_id: &str,
) -> Result<Option<AppletManagedActorPcrAccess>, AppError> {
    let records = crate::routing::extensions::applet_bridge::record::applet_records(state).await?;
    let mut access: Option<AppletManagedActorPcrAccess> = None;
    for record in records {
        let record_active = record.revoked_at.is_none()
            && matches!(record.status.as_str(), "installed" | "partially_installed");
        if record.bot_actor_id.signing_principal_id().as_str() == actor_id {
            if record.bot_actor_id.route_service_id().as_str() != state.service_id() {
                continue;
            }
            let owned_by_session =
                record.identity.initial_package.service_id.as_str() == session_service_id;
            let active_grant_ids = state
                .authorization()
                .grants_for_subject(
                    &arkret_wire::ActorId::service(record.package.service_id.clone()),
                    record.portal_realm_id.as_str(),
                )
                .into_iter()
                .map(|grant| grant.grant_id)
                .collect::<std::collections::BTreeSet<_>>();
            let scope_authority_active = record
                .install_response
                .capability_grant_refs
                .iter()
                .any(|grant_id| active_grant_ids.contains(grant_id.as_str()));
            merge_applet_managed_actor_pcr_access(
                &mut access,
                record.bot_principal_control_realm_id.to_string(),
                owned_by_session,
                record_active,
                scope_authority_active,
                record.identity.globally_fenced_at.is_some(),
            )?;
            continue;
        }
        if let Some(ghost) = record
            .ghosts
            .iter()
            .find(|ghost| ghost.ghost_actor_id.signing_principal_id().as_str() == actor_id)
        {
            if ghost.ghost_actor_id.route_service_id().as_str() != state.service_id() {
                continue;
            }
            let owned_by_session = record.package.service_id.as_str() == session_service_id;
            let ghost_provision = ghost.provision_payload().map_err(|error| {
                AppError::internal(format!(
                    "stored Ghost provision bindings are invalid: {error}"
                ))
            })?;
            let authority_active = state
                .authorization()
                .grants_for_subject(
                    &arkret_wire::ActorId::service(record.package.service_id.clone()),
                    record.portal_realm_id.as_str(),
                )
                .iter()
                .any(|grant| {
                    grant.grant_id.as_str() == ghost_provision.applet_authority_ref.as_str()
                });
            merge_applet_managed_actor_pcr_access(
                &mut access,
                ghost.principal_control_realm_id().to_string(),
                owned_by_session,
                record_active,
                authority_active,
                record.identity.globally_fenced_at.is_some(),
            )?;
        }
    }
    Ok(access)
}

#[cfg(test)]
#[allow(
    clippy::items_after_test_module,
    reason = "the focused regression tests stay adjacent to their private access-merging helper"
)]
mod applet_managed_actor_pcr_access_tests {
    use super::*;

    #[tokio::test]
    async fn submit_idempotency_first_response_uses_exact_actor_and_operation_scope() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let principal = arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let local = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            principal.clone(),
            state.service_core_id(),
        ));
        let foreign = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            principal,
            arkret_wire::DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
        ));
        let first = serde_json::json!({"status": "accepted", "cursor": "opaque-first-response"});
        persist_idempotency_first_response(
            &state,
            &local,
            "test-key",
            "test-request-hash",
            StatusCode::OK,
            &first,
        )
        .await;
        let record = state
            .jobs()
            .scoped_idempotency_record(&local, "ak.self.events.command.submit.v1", "test-key")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.response_body, first);
        assert!(
            state
                .jobs()
                .scoped_idempotency_record(&foreign, "ak.self.events.command.submit.v1", "test-key")
                .await
                .unwrap()
                .is_none()
        );
        for other_operation in ["other.operation.v1", "ak.self.events.command.submit"] {
            assert!(
                state
                    .jobs()
                    .scoped_idempotency_record(&local, other_operation, "test-key")
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[tokio::test]
    async fn canonical_frontier_keeps_same_principal_station_sequences_independent() {
        let state = crate::state::AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let realm = RealmId::new("ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI").unwrap();
        let principal = arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        for (station, sequence) in [("station-a", 7_u64), ("station-b", 20_u64)] {
            let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                principal.clone(),
                arkret_wire::DidCoreId::new(format!("ak:did_core:web:{station}.example")).unwrap(),
            ));
            let event = arkret_wire::test_support::raw_event_for_actor_at(
                "ak.member.state",
                arkret_wire::ScopeRef::Realm {
                    realm_id: realm.clone(),
                },
                actor.clone(),
                sequence,
                arkret_wire::Hlc::new(format!("019041000000-{sequence:04x}-00000001")).unwrap(),
                serde_json::json!({"member_id": actor, "membership": "join", "realm_id": realm}),
                chrono::Utc::now(),
            )
            .unwrap();
            let envelope = serde_json::to_value(&event).unwrap();
            state
                .event_queries()
                .store_canonical_event(soland_services::events::AcceptedEvent {
                    event_id: event.event_id.to_string(),
                    actor_id: actor.to_string(),
                    actor_seq: sequence,
                    realm_id: Some(realm.to_string()),
                    kind: event.kind.to_string(),
                    schema_id: "ak.event.v1".to_owned(),
                    digest_suite: arkret_canonical::DigestSuite::Sha256,
                    canonical_digest: event
                        .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                        .unwrap(),
                    canonical_bytes: crate::routing::events::event_log::event_canonical_bytes(
                        &envelope,
                    )
                    .unwrap(),
                    envelope,
                    received_at: chrono::Utc::now(),
                })
                .await
                .unwrap();
        }
        for (station, expected_sequence) in [("station-a", 8), ("station-b", 21)] {
            let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                principal.clone(),
                arkret_wire::DidCoreId::new(format!("ak:did_core:web:{station}.example")).unwrap(),
            ));
            let frontier = load_realm_actor_frontier(&state, realm.clone(), actor.clone())
                .await
                .unwrap();
            assert_eq!(frontier.actor_id, actor);
            assert_eq!(frontier.next_actor_seq, expected_sequence);
            assert_eq!(frontier.frontier_event_ids.len(), 1);
        }
    }

    #[test]
    fn revoked_sibling_does_not_mask_live_scope_but_global_fence_is_terminal() {
        let mut access = None;
        merge_applet_managed_actor_pcr_access(
            &mut access,
            "ak:realm:shared-pcr".to_owned(),
            true,
            false,
            false,
            false,
        )
        .unwrap();
        merge_applet_managed_actor_pcr_access(
            &mut access,
            "ak:realm:shared-pcr".to_owned(),
            true,
            true,
            true,
            false,
        )
        .unwrap();
        assert!(access.as_ref().unwrap().active);

        merge_applet_managed_actor_pcr_access(
            &mut access,
            "ak:realm:shared-pcr".to_owned(),
            true,
            false,
            false,
            true,
        )
        .unwrap();
        assert!(!access.unwrap().active);
    }

    #[test]
    fn live_scope_with_revoked_authority_is_not_pcr_active() {
        let mut access = None;
        merge_applet_managed_actor_pcr_access(
            &mut access,
            "ak:realm:shared-pcr".to_owned(),
            true,
            true,
            false,
            false,
        )
        .unwrap();
        assert!(!access.unwrap().active);
    }

    #[test]
    fn global_fence_is_terminal_independent_of_installation_iteration_order() {
        let mut access = None;
        merge_applet_managed_actor_pcr_access(
            &mut access,
            "ak:realm:shared-pcr".to_owned(),
            true,
            false,
            false,
            true,
        )
        .unwrap();
        merge_applet_managed_actor_pcr_access(
            &mut access,
            "ak:realm:shared-pcr".to_owned(),
            true,
            true,
            true,
            false,
        )
        .unwrap();
        let access = access.unwrap();
        assert!(access.globally_fenced);
        assert!(!access.active);
    }
}

pub(crate) async fn load_realm_actor_frontier(
    state: &AppState,
    realm_id: RealmId,
    actor_id: arkret_wire::ActorId,
) -> Result<RealmActorFrontierView, AppError> {
    let records = state
        .event_queries()
        .canonical_events_for_realm_actor(realm_id.as_str(), &actor_id.to_string())
        .await
        .map_err(|error| AppError::internal(format!("actor frontier unavailable: {error}")))?;
    let (next_actor_seq, frontier_event_ids) =
        if let Some(max_seq) = records.iter().map(|record| record.actor_seq).max() {
            let next_actor_seq = max_seq.checked_add(1).ok_or_else(|| {
                crate::app_error!(FrontierSequenceExhausted, "actor sequence is exhausted",)
            })?;
            let mut ids = records
                .iter()
                .filter(|record| record.actor_seq == max_seq)
                .map(|record| {
                    EventId::new(record.event_id.clone())
                        .map_err(|_| AppError::internal("stored event_id is invalid"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            ids.sort_by(|left, right| left.as_str().cmp(right.as_str()));
            ids.dedup();
            (next_actor_seq, ids)
        } else {
            (0, Vec::new())
        };
    build_realm_actor_frontier(
        state,
        realm_id,
        actor_id,
        next_actor_seq,
        frontier_event_ids,
    )
}

pub(super) fn build_realm_actor_frontier(
    state: &AppState,
    realm_id: RealmId,
    actor_id: arkret_wire::ActorId,
    next_actor_seq: u64,
    frontier_event_ids: Vec<EventId>,
) -> Result<RealmActorFrontierView, AppError> {
    let suite_name = state
        .projections()
        .snapshot()
        .realm_digest_algorithm(realm_id.as_str())
        .unwrap_or_else(|| "sha256".to_owned());
    let suite = canonical::digest_suite(&suite_name)
        .map_err(|_| AppError::internal("Realm digest algorithm is unsupported"))?;
    RealmActorFrontierView::new(
        realm_id,
        actor_id,
        next_actor_seq,
        frontier_event_ids,
        suite,
    )
    .map_err(|error| AppError::internal(format!("actor frontier is invalid: {error}")))
}
