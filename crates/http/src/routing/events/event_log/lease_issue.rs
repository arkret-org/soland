//! Authority-issued publication leases for final, signed Events.
//!
//! Issuance is a read-only pre-admission pass. It neither stores an Event nor
//! reserves a frontier; the later `events.submit` revalidates everything.

use arkret_wire::SchemaId;
use arkret_wire::offline_publication::{
    AnchorUnitLeaseBasis, AnchorUnitLeaseBasisRef, AuthoritySetAuthorizationRule,
    AuthoritySetIssuer, AuthoritySetIssuerRole, AuthoritySetPolicy, AuthoritySetPolicyKind,
    AuthoritySetPolicySource, AuthoritySetRef, AuthoritySetSourceKind, AuthorizationLease,
    LeaseBasisRef, RiskTier,
};
use arkret_wire::primitives::{Audience, PayloadProof, proof_kind};

use super::*;

const LEASE_TTL_MINUTES: i64 = 10;

#[salvo::oapi::endpoint(
    operation_id = "ak.self.authorization_leases.command.issue",
    tags("events")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.authorization_leases.command.issue.v1"))]
pub(super) async fn issue_authorization_leases(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<arkret_wire::AuthorizationLeaseIssueRequestBody>,
) -> JsonResult<arkret_wire::AuthorizationLeaseIssueOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    super::super::require_agent_session_scope(
        &session,
        arkret_wire::ServiceOperationId::SELF_AUTHORIZATION_LEASES_COMMAND_ISSUE_V1,
    )?;
    let request = body.into_inner();
    request
        .validate_structural()
        .map_err(|error| crate::app_error!(SchemaViolation, error.to_string()))?;
    let idempotency_key = req
        .headers()
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            crate::app_error!(
                ParamMissing,
                "authorization lease issuance requires Idempotency-Key",
            )
        })?;
    let request_hash = arkret_canonical::canonical_sha256(&request).map_err(|error| {
        crate::app_error!(
            SchemaViolation,
            format!("authorization lease request cannot be canonicalized: {error}"),
        )
    })?;
    let authenticated_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(session.actor.clone())
            .map_err(|error| AppError::internal(format!("session actor invalid: {error}")))?,
        state.service_core_id(),
    ));
    match state
        .jobs()
        .scoped_idempotency_record(
            &authenticated_actor,
            "ak.self.authorization_leases.command.issue",
            idempotency_key,
        )
        .await
        .map_err(|error| {
            crate::app_error!(
                InternalError,
                format!("authorization lease idempotency lookup failed: {error}"),
            )
        })? {
        Some(record) if record.request_hash == request_hash => {
            let outcome = serde_json::from_value(record.response_body).map_err(|error| {
                crate::app_error!(
                    InternalError,
                    format!("stored authorization lease outcome is invalid: {error}"),
                )
            })?;
            return json_ok(outcome);
        }
        Some(_) => {
            return Err(crate::app_error!(
                DuplicateConflict,
                "Idempotency-Key was reused with a different lease request",
            ));
        }
        None => {}
    }
    let target_count = request.submissions.len() + request.intents.len();
    if target_count == 0
        || target_count > MAX_EVENT_SUBMIT_BATCH
        || (!request.submissions.is_empty() && !request.intents.is_empty())
    {
        return Err(crate::app_error!(
            SchemaViolation,
            format!(
                "authorization lease issuance requires exactly one non-empty submissions or intents array with at most {MAX_EVENT_SUBMIT_BATCH} entries"
            ),
        ));
    }

    let issued_at = now();
    let expires_at = issued_at + chrono::Duration::minutes(LEASE_TTL_MINUTES);
    let leases = if request.intents.is_empty() {
        issue_event_leases(state, &session, &request.submissions, issued_at, expires_at).await?
    } else {
        issue_intent_leases(state, &session, &request.intents, issued_at, expires_at).await?
    };
    let outcome = arkret_wire::AuthorizationLeaseIssueOutcome {
        authorization_leases: leases,
    };
    let response_body = serde_json::to_value(&outcome).map_err(|error| {
        crate::app_error!(
            InternalError,
            format!("authorization lease outcome cannot be encoded: {error}"),
        )
    })?;
    let created_at = now();
    state
        .jobs()
        .store_idempotency_record(soland_services::jobs::IdempotencyState {
            authenticated_actor,
            operation_id: "ak.self.authorization_leases.command.issue".to_owned(),
            idempotency_key: idempotency_key.to_owned(),
            request_hash,
            response_status: StatusCode::OK.as_u16() as i32,
            response_body,
            created_at,
            expires_at: created_at + chrono::Duration::hours(24),
        })
        .await
        .map_err(|error| {
            crate::app_error!(
                InternalError,
                format!("authorization lease idempotency persist failed: {error}"),
            )
        })?;
    json_ok(outcome)
}

async fn issue_event_leases(
    state: &AppState,
    session: &SessionRecord,
    submissions: &[arkret_wire::EventInitialSubmission],
    issued_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<AuthorizationLease>, AppError> {
    let events = submissions
        .iter()
        .map(|submission| submission.event.clone())
        .collect::<Vec<_>>();
    let context = anchor_context(&events)?;
    if context
        .as_ref()
        .is_some_and(|anchor| anchor.self_principal_pcr_bootstrap)
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "human self-principal PCR genesis MUST NOT carry an AuthorizationLease",
        ));
    }
    let bootstrap_contexts = context
        .as_ref()
        .map(|value| vec![value.bootstrap_context.clone()])
        .unwrap_or_default();
    let mut projected_operations = Vec::with_capacity(events.len());
    let mut projected_cell_writes = Vec::with_capacity(events.len());
    let mut envelopes = Vec::with_capacity(events.len());
    for (event, submission) in events.iter().zip(submissions) {
        let envelope = serde_json::to_value(event).map_err(|error| {
            crate::app_error!(
                SchemaViolation,
                format!("authorization lease Event cannot be encoded: {error}"),
            )
        })?;
        envelopes.push(envelope.clone());
        let parsed = validate_event_envelope_with_context(
            state,
            session,
            &envelope,
            &bootstrap_contexts,
            None,
        )
        .await
        .map_err(event_validation_app_error)?;
        submission
            .validate_structural_in_context(
                if context.is_some() {
                    arkret_wire::EventSubmitContext::AnchorUnit
                } else {
                    arkret_wire::EventSubmitContext::Standard
                },
                parsed.digest_suite,
            )
            .map_err(|error| crate::app_error!(SchemaViolation, error.to_string()))?;
        super::submit::validate_initial_publication_session_context(session, submission).map_err(
            |error| {
                super::submit::submit_one_error_to_app_error(
                    "lease preflight",
                    error.status(),
                    error.code(),
                    &error.message(),
                )
            },
        )?;
        super::governance_proof::validate_transition_leaf_input(
            state,
            event,
            submission.mls_frontier_leaves.as_deref(),
        )
        .await?;
        if let Some(evidence) = &submission.membership_compensation_evidence {
            super::submit::validate_membership_compensation_live_state(state, event, evidence)
                .await
                .map_err(|error| {
                    super::submit::submit_one_error_to_app_error(
                        "lease preflight",
                        error.status(),
                        error.code(),
                        &error.message(),
                    )
                })?;
        }
        let operation = projection_operation_from_event(&parsed, &envelope).ok_or_else(|| {
            crate::app_error!(
                SchemaViolation,
                "authorization lease Event cannot be projected",
            )
        })?;
        projected_operations.push(operation);
        projected_cell_writes.push(
            if context.is_some() {
                genesis_cell_write_projector(event)
            } else {
                state.projections().project_cell_writes(event)
            }
            .map_err(|error| {
                crate::app_error!(
                    SchemaViolation,
                    format!("authorization lease Event cell projection failed: {error}"),
                )
            })?,
        );
    }
    crate::routing::events::operations::validate_operation_semantics(state, &projected_operations)
        .map_err(|reason| {
            crate::app_error!(SchemaViolation, reason).with_internal_reason(reason)
        })?;
    for operation in &projected_operations {
        crate::routing::events::operations::validate_single_operation_policy_in_batch(
            state,
            operation,
            &projected_operations,
            false,
        )
        .await
        .map_err(|reason| {
            let (status, wire_code) =
                crate::routing::events::operations::operation_policy_reason_code(reason);
            let code = match status {
                StatusCode::PRECONDITION_FAILED | StatusCode::UNPROCESSABLE_ENTITY => {
                    ErrorCode::FailedPrecondition
                }
                StatusCode::FORBIDDEN => ErrorCode::CapabilityDenied,
                StatusCode::UNAUTHORIZED => ErrorCode::Unauthenticated,
                StatusCode::CONFLICT => ErrorCode::Conflict,
                _ => ErrorCode::PolicyViolation,
            };
            AppError::from_rejection(code, reason).with_internal_reason(wire_code)
        })?;
    }
    // Lease issuance performs the same reducer admission as a later submit,
    // but against an isolated projection clone. This catches current-state
    // preconditions (for example a same-state membership transition) without
    // storing Events or advancing the accepted frontier.
    if context
        .as_ref()
        .is_some_and(|anchor| anchor.bootstrap_context.authority_root.is_some())
    {
        let projected = projected_operations
            .iter()
            .cloned()
            .zip(projected_cell_writes.iter().cloned())
            .map(
                |(operation, cell_writes)| soland_services::projection::ProjectedOperation {
                    operation,
                    cell_writes,
                },
            )
            .collect::<Vec<_>>();
        state
            .projections()
            .stage_realm_bootstrap(&projected, false)
            .map_err(|error| {
                let rendered = super::submit::realm_bootstrap::bootstrap_projection_error(error);
                super::submit::submit_one_error_to_app_error(
                    "authorization lease Realm bootstrap preflight",
                    rendered.status(),
                    rendered.code(),
                    &rendered.message(),
                )
            })?;
    } else if context.is_some() {
        let projected = projected_operations
            .iter()
            .cloned()
            .zip(projected_cell_writes.iter().cloned())
            .map(
                |(operation, cell_writes)| soland_services::projection::ProjectedOperation {
                    operation,
                    cell_writes,
                },
            )
            .collect::<Vec<_>>();
        state
            .projections()
            .stage_realm_bootstrap(&projected, false)
            .map_err(|error| {
                let rendered = super::submit::realm_bootstrap::bootstrap_projection_error(error);
                super::submit::submit_one_error_to_app_error(
                    "authorization lease genesis preflight",
                    rendered.status(),
                    rendered.code(),
                    &rendered.message(),
                )
            })?;
    } else {
        let mut staged = state.projections().snapshot();
        let hlc = soland_domain::hlc::ServerHlc::new("authorization-lease-preflight");
        let registry = soland_domain::reducer::state_model_kinds::default_cell_family_registry();
        for (operation, cell_writes) in projected_operations
            .iter()
            .zip(projected_cell_writes.iter())
        {
            let contextual_operation = match
                soland_services::operation_semantics::canonical_kind_for_operation(operation)
            {
                Some(arkret_wire::EventKind::MemberState) => Some(
                    crate::routing::events::projection::accepted_member_state_reducer_operation(
                        operation,
                    ),
                ),
                Some(arkret_wire::EventKind::CircleMemberState) => Some(
                    crate::routing::events::projection::accepted_circle_member_reducer_operation(
                        operation,
                    ),
                ),
                _ => None,
            };
            let reducer_operation = contextual_operation.as_ref().unwrap_or(operation);
            if let soland_domain::reducer::ProjectionEffect::Rejected { reason } = staged
                .apply_via_state_model_registry(reducer_operation, cell_writes, &hlc, &registry)
            {
                if soland_services::operation_semantics::canonical_kind_for_operation(operation)
                    == Some(arkret_wire::EventKind::InviteClaim)
                {
                    // third-party-invites.md §6.1: failed claims are
                    // wire-indistinguishable. Keep the reducer reason local.
                    tracing::info!(internal_reason = %reason, "third-party invite claim rejected");
                    return Err(crate::app_error!(NotFound, "invite claim not found"));
                }
                return Err(crate::app_error!(FailedPrecondition, reason.clone())
                    .with_internal_reason(reason));
            }
        }
    }
    let anchor_basis = context.map(|value| value.basis);
    let mut leases = Vec::with_capacity(events.len());
    for event in &events {
        let basis_ref = match &anchor_basis {
            Some(basis) => LeaseBasisRef::AnchorUnit(AnchorUnitLeaseBasisRef {
                anchor_unit: basis.clone(),
            }),
            None => event_basis(event)?,
        };
        let (action, risk_tier) = publication_action(event.kind.as_str());
        let (authority_set_ref, authority_set_policy) =
            realm_admission_authority(state, event, &basis_ref, &action)?;
        leases.push(sign_lease(
            state,
            session,
            event,
            basis_ref,
            action,
            risk_tier,
            authority_set_ref,
            authority_set_policy,
            issued_at,
            expires_at,
        )?);
    }
    Ok(leases)
}

/// Lease issuance runs the same pre-admission validator as Event submission.
/// Preserve its canonical wire code and stable reason instead of flattening
/// every refusal to `policy_violation`; clients use typed preconditions such as
/// `mls_governance_binding_stale` to schedule the protocol-mandated repair.
fn event_validation_app_error(error: EventValidationError) -> AppError {
    let code = ErrorCode::from_wire(error.code).unwrap_or(ErrorCode::PolicyViolation);
    let mut rendered = AppError::from_rejection(code, error.message);
    if let Some(reason_code) = error.reason_code {
        rendered = rendered.with_reason_code(reason_code);
    }
    rendered
}

async fn issue_intent_leases(
    state: &AppState,
    session: &SessionRecord,
    intents: &[arkret_wire::AuthorizationLeaseIssueIntent],
    issued_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<AuthorizationLease>, AppError> {
    let actor_id =
        crate::routing::identity::session_actor::session_actor_from_credential(state, session)?;
    let device_id = arkret_wire::DeviceId::new(session.device_id.clone()).map_err(|error| {
        crate::app_error!(
            PolicyViolation,
            format!("session device id is invalid: {error}"),
        )
    })?;
    let mut leases = Vec::with_capacity(intents.len());
    for intent in intents {
        let descriptor = arkret_schema::capability_action(&intent.action).ok_or_else(|| {
            crate::app_error!(
                SchemaViolation,
                "authorization lease intent action is not registered",
            )
        })?;
        let expected_risk = match descriptor.risk_tier {
            arkret_schema::CapabilityRiskTier::Low => RiskTier::Low,
            arkret_schema::CapabilityRiskTier::Medium => RiskTier::Medium,
            arkret_schema::CapabilityRiskTier::High => RiskTier::High,
        };
        if !descriptor.target_event_kinds.is_empty()
            || intent.risk_tier != expected_risk
            || intent.authorization_rule_id != "realm_admission"
            || !state
                .projections()
                .snapshot()
                .realm_is_principal_control_for_actor(
                    intent.scope_ref.realm_id().as_str(),
                    &actor_id.to_string(),
                )
        {
            return Err(crate::app_error!(
                CapabilityDenied,
                "authorization lease intent is not a matching principal-control non-Event action",
            ));
        }
        match &intent.basis_ref {
            LeaseBasisRef::Seal(seal_id) => {
                let seal = state
                    .projections()
                    .seal_by_id(seal_id)
                    .await
                    .map_err(|error| AppError::internal(error.to_string()))?
                    .ok_or_else(|| {
                        AppError::conflict("authorization lease intent basis is not accepted")
                            .with_internal_reason("authorization_lease_basis_mismatch")
                    })?;
                if seal.realm_id != *intent.scope_ref.realm_id() {
                    return Err(AppError::conflict(
                        "authorization lease intent basis is in another Realm",
                    )
                    .with_internal_reason("authorization_lease_basis_mismatch"));
                }
            }
            _ => {
                return Err(crate::app_error!(
                    SchemaViolation,
                    "non-Event authorization lease intent requires an accepted Seal basis",
                ));
            }
        }
        let (authority_set_ref, authority_set_policy) = authority_for_scope(
            state,
            &intent.scope_ref,
            &intent.basis_ref,
            &intent.action,
            &intent.authorization_rule_id,
        )?;
        leases.push(sign_lease_fields(
            state,
            actor_id.clone(),
            device_id.clone(),
            intent.scope_ref.clone(),
            intent.basis_ref.clone(),
            intent.action.clone(),
            intent.authorization_rule_id.clone(),
            intent.risk_tier,
            authority_set_ref,
            authority_set_policy,
            issued_at,
            expires_at,
        )?);
    }
    Ok(leases)
}

struct AnchorIssueContext {
    bootstrap_context: RealmBootstrapBatchContext,
    basis: AnchorUnitLeaseBasis,
    self_principal_pcr_bootstrap: bool,
}

fn anchor_context(events: &[Event]) -> Result<Option<AnchorIssueContext>, AppError> {
    if events
        .first()
        .is_none_or(|event| event.kind != arkret_wire::EventKind::RealmCreate)
    {
        return Ok(None);
    }
    let (realm_id, actor_id, self_principal_pcr_bootstrap, authority_root) = if events.len() == 2
        && events
            .get(1)
            .is_some_and(|event| event.kind == arkret_wire::EventKind::DeviceAuthorize)
    {
        arkret_bootstrap::validate_self_principal_pcr_genesis_unit(
            &events[0],
            &events[1],
            &genesis_cell_write_projector,
        )
        .map_err(|error| {
            crate::app_error!(
                SchemaViolation,
                format!("invalid self-principal anchor unit: {error}"),
            )
        })?;
        (
            events[0].realm_id.as_str().to_owned(),
            events[0].actor_id.to_string(),
            true,
            None,
        )
    } else if events.len() == 1
        && events[0].executed_by.as_ref() != Some(&events[0].actor_id)
        && arkret_bootstrap::materialize_agent_pcr_control(events, &genesis_cell_write_projector)
            .is_ok()
    {
        (
            events[0].realm_id.as_str().to_owned(),
            events[0].actor_id.to_string(),
            false,
            None,
        )
    } else {
        let unit = arkret_policy::realm_bootstrap::validate_realm_bootstrap_unit(events).map_err(
            |error| {
                crate::app_error!(
                    SchemaViolation,
                    format!("invalid Realm anchor unit: {error}"),
                )
            },
        )?;
        (
            unit.realm_id.to_string(),
            unit.actor_id.to_string(),
            false,
            Some(unit.authority_root),
        )
    };
    let genesis_live_digest_suite = arkret::declared_genesis_live_digest_suite(&events[0])
        .map_err(|error| crate::app_error!(SchemaViolation, error.to_string()))?;
    let event_digests = events
        .iter()
        .map(|event| {
            let digest_suite = if event.kind == arkret_wire::EventKind::RealmCreate {
                arkret_canonical::DigestSuite::Sha256
            } else {
                genesis_live_digest_suite
            };
            let digest = event
                .event_digest_with_digest_suite(digest_suite)
                .map_err(|error| {
                    crate::app_error!(
                        SchemaViolation,
                        format!("anchor Event digest failed: {error}"),
                    )
                })?;
            arkret_identifiers::Hash::new(digest).map_err(|error| {
                crate::app_error!(
                    SchemaViolation,
                    format!("anchor Event digest is invalid: {error}"),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut basis = AnchorUnitLeaseBasis {
        realm_id: arkret_identifiers::RealmId::new(realm_id.clone()).map_err(|error| {
            crate::app_error!(
                SchemaViolation,
                format!("anchor realm_id is invalid: {error}"),
            )
        })?,
        event_digests,
        unit_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "0".repeat(64)))
            .expect("fixed digest is valid"),
    };
    basis.unit_digest = basis.expected_unit_digest().map_err(|error| {
        crate::app_error!(
            SchemaViolation,
            format!("anchor unit digest failed: {error}"),
        )
    })?;
    Ok(Some(AnchorIssueContext {
        bootstrap_context: RealmBootstrapBatchContext {
            realm_id,
            actor_id,
            digest_algorithm: Some(super::submit::staged_realm_digest_algorithm(
                &serde_json::to_value(&events[0]).map_err(|error| {
                    crate::app_error!(
                        SchemaViolation,
                        format!("anchor Realm-create Event cannot be encoded: {error}"),
                    )
                })?,
            )),
            identity_anchor_event_id: if self_principal_pcr_bootstrap {
                Some(events[0].event_id.as_str().to_owned())
            } else {
                None
            },
            identity_anchor_candidate_device: None,
            identity_anchor_resolution: None,
            direct_conversation_founding: false,
            authority_root,
        },
        basis,
        self_principal_pcr_bootstrap,
    }))
}

fn event_basis(event: &Event) -> Result<LeaseBasisRef, AppError> {
    if let Some(context) = &event.auth_context {
        let [authority_ref] = context.authority_refs.as_slice() else {
            return Err(crate::app_error!(
                SchemaViolation,
                "Event lease issuance requires one authority reference",
            ));
        };
        return Ok(LeaseBasisRef::Seal(authority_ref.clone()));
    }
    if let Some(seal_basis) = &event.seal_basis {
        return Ok(LeaseBasisRef::Joined(seal_basis.clone()));
    }
    Err(crate::app_error!(
        SchemaViolation,
        "non-anchor Event lease issuance requires authority_refs or seal_basis",
    ))
}

fn publication_action(kind: &str) -> (String, RiskTier) {
    let candidates = arkret_schema::REGISTERED_CAPABILITY_ACTIONS
        .iter()
        .filter(|descriptor| descriptor.target_event_kinds.contains(&kind))
        .collect::<Vec<_>>();
    let selected = candidates
        .iter()
        .copied()
        .find(|descriptor| descriptor.action.as_str() == kind)
        .or_else(|| {
            candidates.iter().copied().find(|descriptor| {
                descriptor.action.as_str() == arkret_wire::CapabilityActionId::REALM_ADMIN
            })
        })
        .or_else(|| candidates.first().copied());
    selected.map_or_else(
        || (kind.to_owned(), RiskTier::High),
        |descriptor| {
            let risk = match descriptor.risk_tier {
                arkret_schema::CapabilityRiskTier::Low => RiskTier::Low,
                arkret_schema::CapabilityRiskTier::Medium => RiskTier::Medium,
                arkret_schema::CapabilityRiskTier::High => RiskTier::High,
            };
            (descriptor.action.as_str().to_owned(), risk)
        },
    )
}

pub(super) fn bootstrap_ingress_authority_set_refs(
    state: &AppState,
    events: &[Event],
) -> Result<Vec<AuthoritySetRef>, String> {
    let basis = anchor_context(events)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "closed genesis ingress authority requires an AnchorUnit".to_owned())?
        .basis;
    let basis_ref = LeaseBasisRef::AnchorUnit(AnchorUnitLeaseBasisRef { anchor_unit: basis });
    events
        .iter()
        .map(|event| {
            let (action, _) = publication_action(event.kind.as_str());
            realm_admission_authority(state, event, &basis_ref, &action)
                .map(|(reference, _)| reference)
                .map_err(|error| error.to_string())
        })
        .collect()
}

fn realm_admission_authority(
    state: &AppState,
    event: &Event,
    basis_ref: &LeaseBasisRef,
    action: &str,
) -> Result<(AuthoritySetRef, AuthoritySetPolicy), AppError> {
    authority_for_scope(
        state,
        &event.scope_ref,
        basis_ref,
        action,
        "realm_admission",
    )
}

pub(crate) fn authority_for_scope(
    state: &AppState,
    scope_ref: &arkret_wire::ScopeRef,
    basis_ref: &LeaseBasisRef,
    action: &str,
    authorization_rule_id: &str,
) -> Result<(AuthoritySetRef, AuthoritySetPolicy), AppError> {
    // Publication admission and Seal notarization are distinct authorities.
    // The concrete policy freezes the exact accepted basis, scope, action and
    // service verification method that performed the full pre-admission pass.
    let source_digest = arkret_identifiers::Hash::new(
        arkret_canonical::canonical_sha256(basis_ref).map_err(|error| {
            crate::app_error!(
                InternalError,
                format!("lease authority basis digest failed: {error}"),
            )
        })?,
    )
    .map_err(|error| {
        crate::app_error!(
            InternalError,
            format!("lease authority basis digest is invalid: {error}"),
        )
    })?;
    let verification_method = arkret_wire::DidUrl::new(format!(
        "{}#notary-key",
        state.service_resolution_commitment().did
    ))
    .map_err(|error| {
        crate::app_error!(
            InternalError,
            format!("lease authority verification method is invalid: {error}"),
        )
    })?;
    let policy = AuthoritySetPolicy {
        schema: SchemaId::AUTHORITY_SET_POLICY_V1.to_owned(),
        authority_set_id: arkret_wire::AuthoritySetId::REALM_ADMISSION_V1.to_owned(),
        policy_kind: AuthoritySetPolicyKind::RealmAdmission,
        scope_ref: scope_ref.clone(),
        source: AuthoritySetPolicySource {
            source_kind: AuthoritySetSourceKind::RealmControl,
            source_ref: format!("basis:{}", source_digest.as_str()),
            source_digest: source_digest.clone(),
            generation_ref: format!("basis:{}", basis_generation_ref(basis_ref, &source_digest)),
        },
        authorization_rules: vec![AuthoritySetAuthorizationRule {
            rule_id: authorization_rule_id.to_owned(),
            issuer_role: AuthoritySetIssuerRole::RealmAdmission,
            allowed_actions: vec![action.to_owned()],
            issuers: vec![AuthoritySetIssuer {
                verification_method,
            }],
            threshold: 1,
        }],
    };
    let authority_set_digest = policy.digest().map_err(lease_internal_error)?;
    let reference = AuthoritySetRef {
        authority_set_id: arkret_wire::AuthoritySetId::REALM_ADMISSION_V1.to_owned(),
        authority_set_digest,
    };
    Ok((reference, policy))
}

fn basis_generation_ref(
    basis_ref: &LeaseBasisRef,
    source_digest: &arkret_identifiers::Hash,
) -> String {
    match basis_ref {
        LeaseBasisRef::Seal(seal) => seal.as_str().to_owned(),
        LeaseBasisRef::Joined(_) => source_digest.as_str().to_owned(),
        LeaseBasisRef::AnchorUnit(reference) => {
            reference.anchor_unit.unit_digest.as_str().to_owned()
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn sign_lease(
    state: &AppState,
    session: &SessionRecord,
    event: &Event,
    basis_ref: LeaseBasisRef,
    action: String,
    risk_tier: RiskTier,
    authority_set_ref: AuthoritySetRef,
    authority_set_policy: AuthoritySetPolicy,
    issued_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> Result<AuthorizationLease, AppError> {
    let actor_id = event
        .proofs
        .iter()
        .find_map(|proof| {
            let (controller, _) = proof.verification_method.rsplit_once('#')?;
            let did = arkret_wire::Did::new(controller.to_owned()).ok()?;
            (arkret_wire::project_did_to_core_id(&did).ok().as_ref()
                == Some(event.actor_id.signing_principal_id()))
            .then_some(event.actor_id.clone())
        })
        .ok_or_else(|| {
            crate::app_error!(
                SignatureInvalid,
                "Event has no proof controller that projects to actor_id",
            )
        })?;
    sign_lease_fields(
        state,
        actor_id,
        arkret_identifiers::DeviceId::new(session.device_id.clone()).map_err(|error| {
            crate::app_error!(
                PolicyViolation,
                format!("session device id is invalid: {error}"),
            )
        })?,
        event.scope_ref.clone(),
        basis_ref,
        action,
        "realm_admission".to_owned(),
        risk_tier,
        authority_set_ref,
        authority_set_policy,
        issued_at,
        expires_at,
    )
}

#[allow(clippy::too_many_arguments)]
fn sign_lease_fields(
    state: &AppState,
    actor_id: arkret_wire::ActorId,
    device_id: arkret_wire::DeviceId,
    scope_ref: arkret_wire::ScopeRef,
    basis_ref: LeaseBasisRef,
    action: String,
    authorization_rule_id: String,
    risk_tier: RiskTier,
    authority_set_ref: AuthoritySetRef,
    authority_set_policy: AuthoritySetPolicy,
    issued_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> Result<AuthorizationLease, AppError> {
    let mut lease = AuthorizationLease {
        authorization_lease_id: arkret_identifiers::AuthorizationLeaseId::new(
            crate::ids::generate("authorization_lease"),
        )
        .map_err(|error| {
            crate::app_error!(
                InternalError,
                format!("minted authorization lease id is invalid: {error}"),
            )
        })?,
        basis_ref,
        actor_id,
        device_id,
        scope_ref,
        action,
        authorization_rule_id,
        risk_tier,
        issued_at,
        expires_at,
        authority_set_ref,
        authority_set_policy,
        proofs: Vec::new(),
    };
    let digest = lease.lease_digest().map_err(lease_internal_error)?;
    let mut proof = PayloadProof {
        kind: proof_kind::DETACHED_JWS.to_owned(),
        verification_method: arkret_wire::DidUrl::new(format!(
            "{}#notary-key",
            state.service_resolution_commitment().did
        ))
        .map_err(lease_internal_error)?,
        payload_digest: digest,
        created_at: issued_at,
        domain: None,
        audience: Some(Audience::Single(
            state.service_resolution_commitment().did.to_string(),
        )),
        proof_purpose: None,
        jws: String::new(),
    };
    let binding = lease
        .proof_binding_bytes(&proof)
        .map_err(lease_internal_error)?;
    proof.jws =
        arkret_signatures::jws::sign_jws_ed25519(&binding, state.notary_signing_key().as_ref())
            .map_err(|error| {
                crate::app_error!(
                    InternalError,
                    format!("authorization lease signing failed: {error}"),
                )
            })?;
    lease.proofs = vec![proof];
    lease.validate_structural().map_err(lease_internal_error)?;
    Ok(lease)
}

fn lease_internal_error(error: impl std::fmt::Display) -> AppError {
    crate::app_error!(
        InternalError,
        format!("minted authorization lease is invalid: {error}"),
    )
}

#[cfg(test)]
mod tests {
    use arkret_wire::{Event, EventKind, Hlc, RealmId, ScopeRef, SealId};
    use serde_json::json;
    use soland_storage_postgres::Db;

    use super::*;

    const REALM: &str = "ak:realm:AdLYeSYbF1FJx56D-sYzJ--z1eUpXoCui7ZQTBhWJbKp";
    const ACTOR: &str = "did:web:alice.local.host";
    const ACTOR_CORE: &str = "ak:did_core:web:alice.local.host";
    fn event(kind: impl AsRef<str>, actor_seq: u64, payload: Value) -> Event {
        crate::test_event::raw_event_at(
            kind.as_ref(),
            ScopeRef::Realm {
                realm_id: RealmId::new(REALM).expect("fixture Realm id"),
            },
            crate::test_actor_id_str(ACTOR),
            actor_seq,
            Hlc::new(format!("019fbb72ef34-{actor_seq:04x}-a13f9c2e")).expect("fixture HLC"),
            payload,
            chrono::Utc::now(),
        )
        .expect("fixture Event")
    }

    #[test]
    fn ordinary_anchor_lease_context_preserves_staged_authority_root_for_followups() {
        let create = event(
            EventKind::RealmCreate,
            0,
            json!({"object": {
                "schema": "ak.schema.realm_genesis.v1",
                "purpose": "collaboration",
                "genesis_salt": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "trust_domain": "ak:trust_domain:example.net",
                "schema_refs": ["ak.schema.realm.v1"],
                "reducer_profile": "ak.reducer.core.v1",
                "digest_algorithm": "sha256",
                "security_class": "standard",
                "encryption_profile": "none",
                "notary": serde_json::to_value(crate::test_f0_notary(
                    ACTOR,
                    33,
                )).unwrap()
            }}),
        );
        let mut creator_member = event(
            EventKind::MemberState,
            7,
            json!({
                "realm_id": REALM,
                "member_id": create.actor_id,
                "membership": "join"
            }),
        );
        let member_cell = arkret_schema::project_registered_cell_writes(
            &creator_member,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap()
        .into_iter()
        .find(|write| {
            write
                .cell_id
                .as_str()
                .starts_with("ak:cell:ak.component.member.state.v1:")
        })
        .unwrap()
        .cell_id;
        creator_member.preconditions = vec![
            serde_json::from_value(json!({
                "cell_id": member_cell,
                "predicate": { "op": "head_eq", "value": null }
            }))
            .expect("creator member head_eq precondition"),
        ];
        let events = vec![
            create,
            event(
                EventKind::RealmProfile,
                1,
                json!({"schema": "ak.schema.realm_profile.v1", "title": "Realm"}),
            ),
            event(
                EventKind::RealmPolicyBundle,
                2,
                json!({"policy_revision": 1}),
            ),
            event(EventKind::RealmJoinRule, 3, json!({"value": "invite"})),
            event(
                EventKind::RealmHistoryAccess,
                4,
                json!({"from": null, "to": "since_join"}),
            ),
            event(
                EventKind::RealmDiscovery,
                5,
                json!({"value": "invite_only"}),
            ),
            creator_member,
        ];

        let context = anchor_context(&events)
            .expect("ordinary Realm anchor unit is valid")
            .expect("ordinary Realm anchor unit has a lease context");
        assert_eq!(
            context.bootstrap_context.digest_algorithm.as_deref(),
            Some("sha256"),
            "lease pre-admission must stage the genesis digest suite for follow-ups",
        );
        let root = context
            .bootstrap_context
            .authority_root
            .expect("staged authority root must survive lease pre-admission");

        assert!(root.is_genesis_for(&events[0].actor_id));
    }

    #[test]
    fn lease_pre_admission_preserves_typed_validation_failure() {
        let error = event_validation_app_error(EventValidationError {
            status: StatusCode::CONFLICT,
            code: arkret_wire::ErrorCode::FAILED_PRECONDITION,
            message: format!(
                "{}: security_frontier_digest is stale",
                arkret_wire::ReasonCode::MLS_GOVERNANCE_BINDING_STALE
            ),
            reason_code: Some(arkret_wire::ReasonCode::MLS_GOVERNANCE_BINDING_STALE),
        });

        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert_eq!(
            error.http_status(),
            soland_http::error::error_http_status(error.code)
        );
        assert_eq!(
            error.reason_code.as_deref(),
            Some(arkret_wire::ReasonCode::MLS_GOVERNANCE_BINDING_STALE)
        );
    }

    #[test]
    fn lease_authority_and_proof_use_service_did_not_projected_core_id() {
        let state = AppState::new(crate::config::AppConfig::test_default(), Db { pool: None });
        assert!(state.service_id().starts_with("ak:did_core:"));

        let scope_ref = ScopeRef::Realm {
            realm_id: RealmId::new(REALM).expect("fixture Realm id"),
        };
        let basis_ref = LeaseBasisRef::Seal(
            SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).expect("fixture Seal id"),
        );
        let (authority_set_ref, authority_set_policy) = authority_for_scope(
            &state,
            &scope_ref,
            &basis_ref,
            "ak.realm.create",
            "realm_admission",
        )
        .expect("service DID must form a legal authority verification method");

        let expected_method = arkret_wire::DidUrl::new(format!(
            "{}#notary-key",
            state.service_resolution_commitment().did
        ))
        .expect("fixture service DID method");
        assert_eq!(
            authority_set_policy.authorization_rules[0].issuers[0].verification_method,
            expected_method
        );

        let issued_at = chrono::Utc::now();
        let lease = sign_lease_fields(
            &state,
            arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new(ACTOR_CORE).expect("fixture actor CoreId"),
                state.service_core_id().clone(),
            )),
            arkret_wire::DeviceId::new("ak:device:019f0000-0000-7000-8000-00000000de01")
                .expect("fixture device id"),
            scope_ref,
            basis_ref,
            "ak.realm.create".to_owned(),
            "realm_admission".to_owned(),
            RiskTier::High,
            authority_set_ref,
            authority_set_policy,
            issued_at,
            issued_at + chrono::Duration::minutes(5),
        )
        .expect("service DID must form a legal lease proof method");
        assert_eq!(lease.proofs[0].verification_method, expected_method);
    }
}
