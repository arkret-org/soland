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
#[tracing::instrument(skip_all, fields(op = "ak.self.authorization_leases.command.issue"))]
pub(super) async fn issue_authorization_leases(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<arkret_wire::AuthorizationLeaseIssueRequest>,
) -> JsonResult<arkret_wire::AuthorizationLeaseIssueOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    super::super::require_agent_session_scope(
        &session,
        "ak.self.authorization_leases.command.issue",
    )?;
    let request = body.into_inner();
    let idempotency_key = req
        .headers()
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::MissingParam,
                "authorization lease issuance requires Idempotency-Key",
            )
            .with_status(StatusCode::BAD_REQUEST)
        })?;
    let request_hash = arkret_canonical::canonical_sha256(&request).map_err(|error| {
        AppError::new(
            ErrorCode::SchemaViolation,
            format!("authorization lease request cannot be canonicalized: {error}"),
        )
        .with_status(StatusCode::BAD_REQUEST)
    })?;
    match state
        .jobs()
        .idempotency_record(&session.actor, idempotency_key)
        .await
        .map_err(|error| {
            AppError::new(
                ErrorCode::InternalError,
                format!("authorization lease idempotency lookup failed: {error}"),
            )
        })? {
        Some(record) if record.request_hash == request_hash => {
            let outcome = serde_json::from_value(record.response_body).map_err(|error| {
                AppError::new(
                    ErrorCode::InternalError,
                    format!("stored authorization lease outcome is invalid: {error}"),
                )
            })?;
            return json_ok(outcome);
        }
        Some(_) => {
            return Err(AppError::new(
                ErrorCode::DuplicateConflict,
                "Idempotency-Key was reused with a different lease request",
            )
            .with_status(StatusCode::CONFLICT));
        }
        None => {}
    }
    let target_count = request.events.len() + request.intents.len();
    if target_count == 0
        || target_count > MAX_EVENT_SUBMIT_BATCH
        || (!request.events.is_empty() && !request.intents.is_empty())
    {
        return Err(AppError::new(
            ErrorCode::SchemaViolation,
            format!(
                "authorization lease issuance requires exactly one non-empty events or intents array with at most {MAX_EVENT_SUBMIT_BATCH} entries"
            ),
        )
        .with_status(StatusCode::BAD_REQUEST));
    }

    let issued_at = now();
    let expires_at = issued_at + chrono::Duration::minutes(LEASE_TTL_MINUTES);
    let leases = if request.intents.is_empty() {
        issue_event_leases(state, &session, &request.events, issued_at, expires_at).await?
    } else {
        issue_intent_leases(state, &session, &request.intents, issued_at, expires_at).await?
    };
    let outcome = arkret_wire::AuthorizationLeaseIssueOutcome {
        authorization_leases: leases,
    };
    let response_body = serde_json::to_value(&outcome).map_err(|error| {
        AppError::new(
            ErrorCode::InternalError,
            format!("authorization lease outcome cannot be encoded: {error}"),
        )
    })?;
    let created_at = now();
    state
        .jobs()
        .store_idempotency_record(soland_services::jobs::IdempotencyState {
            principal_id: session.actor.clone(),
            idempotency_key: idempotency_key.to_owned(),
            service_id: state.service_id().clone(),
            request_hash,
            response_status: StatusCode::OK.as_u16() as i32,
            response_body,
            created_at,
            expires_at: created_at + chrono::Duration::hours(24),
        })
        .await
        .map_err(|error| {
            AppError::new(
                ErrorCode::InternalError,
                format!("authorization lease idempotency persist failed: {error}"),
            )
        })?;
    json_ok(outcome)
}

async fn issue_event_leases(
    state: &AppState,
    session: &SessionRecord,
    events: &[Event],
    issued_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<AuthorizationLease>, AppError> {
    let context = anchor_context(events)?;
    let bootstrap_contexts = context
        .as_ref()
        .map(|value| vec![value.bootstrap_context.clone()])
        .unwrap_or_default();
    for event in events {
        let envelope = serde_json::to_value(event).map_err(|error| {
            AppError::new(
                ErrorCode::SchemaViolation,
                format!("authorization lease Event cannot be encoded: {error}"),
            )
            .with_status(StatusCode::BAD_REQUEST)
        })?;
        validate_event_envelope_with_context(state, session, &envelope, &bootstrap_contexts, None)
            .await
            .map_err(event_validation_app_error)?;
    }
    let anchor_basis = context.map(|value| value.basis);
    let mut leases = Vec::with_capacity(events.len());
    for event in events {
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
    let mut rendered = AppError::new(code, error.message).with_status(error.status);
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
    let actor_id = arkret_wire::Did::new(session.actor.clone()).map_err(|error| {
        AppError::new(
            ErrorCode::PolicyViolation,
            format!("session actor DID is invalid: {error}"),
        )
        .with_status(StatusCode::FORBIDDEN)
    })?;
    let device_id = arkret_wire::DeviceId::new(session.device_id.clone()).map_err(|error| {
        AppError::new(
            ErrorCode::PolicyViolation,
            format!("session device id is invalid: {error}"),
        )
        .with_status(StatusCode::FORBIDDEN)
    })?;
    let expected_realm =
        soland_services::identity::principal_control_realm_for_did(actor_id.as_str());
    let mut leases = Vec::with_capacity(intents.len());
    for intent in intents {
        let descriptor = arkret_schema::capability_action(&intent.action).ok_or_else(|| {
            AppError::new(
                ErrorCode::SchemaViolation,
                "authorization lease intent action is not registered",
            )
            .with_status(StatusCode::BAD_REQUEST)
        })?;
        let expected_risk = match descriptor.risk_tier {
            arkret_schema::CapabilityRiskTier::Low => RiskTier::Low,
            arkret_schema::CapabilityRiskTier::Medium => RiskTier::Medium,
            arkret_schema::CapabilityRiskTier::High => RiskTier::High,
        };
        if !descriptor.target_event_kinds.is_empty()
            || intent.risk_tier != expected_risk
            || intent.authorization_rule_id != "realm_admission"
            || intent.scope_ref.realm_id().as_str() != expected_realm
        {
            return Err(AppError::new(
                ErrorCode::CapabilityDenied,
                "authorization lease intent is not a matching principal-control non-Event action",
            )
            .with_status(StatusCode::FORBIDDEN));
        }
        match &intent.basis_ref {
            LeaseBasisRef::Seal(seal_id) => {
                let seal = state
                    .projections()
                    .seal_by_id(seal_id)
                    .map_err(|error| AppError::internal(error.to_string()))?
                    .ok_or_else(|| {
                        AppError::conflict("authorization lease intent basis is not accepted")
                            .with_wire_code("authorization_lease_basis_mismatch")
                    })?;
                if seal.realm_id != *intent.scope_ref.realm_id() {
                    return Err(AppError::conflict(
                        "authorization lease intent basis is in another Realm",
                    )
                    .with_wire_code("authorization_lease_basis_mismatch"));
                }
            }
            _ => {
                return Err(AppError::new(
                    ErrorCode::SchemaViolation,
                    "non-Event authorization lease intent requires an accepted Seal basis",
                )
                .with_status(StatusCode::BAD_REQUEST));
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
}

fn anchor_context(events: &[Event]) -> Result<Option<AnchorIssueContext>, AppError> {
    if events
        .first()
        .is_none_or(|event| event.kind.as_str() != arkret_wire::EventKind::REALM_CREATE)
    {
        return Ok(None);
    }
    let (realm_id, actor_id, self_principal_pcr_bootstrap, authority_root) = if events.len() == 2
        && events
            .get(1)
            .is_some_and(|event| event.kind.as_str() == arkret_wire::EventKind::DEVICE_AUTHORIZE)
    {
        arkret_bootstrap::validate_self_principal_bootstrap_unit(
            &events[0],
            &events[1],
            &genesis_cell_write_projector,
        )
        .map_err(|error| {
            AppError::new(
                ErrorCode::SchemaViolation,
                format!("invalid self-principal anchor unit: {error}"),
            )
            .with_status(StatusCode::BAD_REQUEST)
        })?;
        (
            events[0].realm_id.as_str().to_owned(),
            events[0].actor_id.as_str().to_owned(),
            true,
            None,
        )
    } else if events.len() == 1
        && events[0].executed_by.as_ref() != Some(&events[0].actor_id)
        && arkret_bootstrap::materialize_managed_agent_pcr_control(
            events,
            &genesis_cell_write_projector,
        )
        .is_ok()
    {
        (
            events[0].realm_id.as_str().to_owned(),
            events[0].actor_id.as_str().to_owned(),
            false,
            None,
        )
    } else {
        let unit = arkret_policy::realm_bootstrap::validate_realm_bootstrap_unit(events).map_err(
            |error| {
                AppError::new(
                    ErrorCode::SchemaViolation,
                    format!("invalid Realm anchor unit: {error}"),
                )
                .with_status(StatusCode::BAD_REQUEST)
            },
        )?;
        (
            unit.realm_id,
            unit.actor_id,
            false,
            Some(unit.authority_root),
        )
    };
    let event_digests = events
        .iter()
        .map(|event| {
            let digest = event.event_digest().map_err(|error| {
                AppError::new(
                    ErrorCode::SchemaViolation,
                    format!("anchor Event digest failed: {error}"),
                )
                .with_status(StatusCode::BAD_REQUEST)
            })?;
            arkret_identifiers::Hash::new(digest).map_err(|error| {
                AppError::new(
                    ErrorCode::SchemaViolation,
                    format!("anchor Event digest is invalid: {error}"),
                )
                .with_status(StatusCode::BAD_REQUEST)
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut basis = AnchorUnitLeaseBasis {
        realm_id: arkret_identifiers::RealmId::new(realm_id.clone()).map_err(|error| {
            AppError::new(
                ErrorCode::SchemaViolation,
                format!("anchor realm_id is invalid: {error}"),
            )
            .with_status(StatusCode::BAD_REQUEST)
        })?,
        event_digests,
        unit_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "0".repeat(64)))
            .expect("fixed digest is valid"),
    };
    basis.unit_digest = basis.expected_unit_digest().map_err(|error| {
        AppError::new(
            ErrorCode::SchemaViolation,
            format!("anchor unit digest failed: {error}"),
        )
        .with_status(StatusCode::BAD_REQUEST)
    })?;
    Ok(Some(AnchorIssueContext {
        bootstrap_context: RealmBootstrapBatchContext {
            realm_id,
            actor_id,
            identity_anchor_event_id: if self_principal_pcr_bootstrap {
                Some(events[0].event_id.as_str().to_owned())
            } else {
                None
            },
            self_principal_pcr_bootstrap,
            authority_root,
        },
        basis,
    }))
}

fn event_basis(event: &Event) -> Result<LeaseBasisRef, AppError> {
    if let Some(seal_ref) = &event.seal_ref {
        return Ok(LeaseBasisRef::Seal(seal_ref.clone()));
    }
    if let Some(seal_basis) = &event.seal_basis {
        return Ok(LeaseBasisRef::Joined(seal_basis.clone()));
    }
    Err(AppError::new(
        ErrorCode::SchemaViolation,
        "non-anchor Event lease issuance requires seal_ref or seal_basis",
    )
    .with_status(StatusCode::BAD_REQUEST))
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
            candidates
                .iter()
                .copied()
                .find(|descriptor| descriptor.action.as_str() == "ak.realm.admin")
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
            AppError::new(
                ErrorCode::InternalError,
                format!("lease authority basis digest failed: {error}"),
            )
        })?,
    )
    .map_err(|error| {
        AppError::new(
            ErrorCode::InternalError,
            format!("lease authority basis digest is invalid: {error}"),
        )
    })?;
    let verification_method =
        arkret_wire::DidUrl::new(format!("{}#notary-key", state.service_id())).map_err(
            |error| {
                AppError::new(
                    ErrorCode::InternalError,
                    format!("lease authority verification method is invalid: {error}"),
                )
            },
        )?;
    let policy = AuthoritySetPolicy {
        schema: SchemaId::AUTHORITY_SET_POLICY_V1.to_owned(),
        authority_set_id: "ak.authority_set.realm_admission.v1".to_owned(),
        policy_kind: AuthoritySetPolicyKind::RealmAdmission,
        scope_ref: scope_ref.clone(),
        source: AuthoritySetPolicySource {
            source_kind: AuthoritySetSourceKind::RealmControl,
            source_ref: format!("basis:{}", source_digest.as_str()),
            source_digest,
            generation_ref: format!("basis:{}", basis_generation_ref(basis_ref)),
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
        authority_set_id: "ak.authority_set.realm_admission.v1".to_owned(),
        authority_set_digest,
    };
    Ok((reference, policy))
}

fn basis_generation_ref(basis_ref: &LeaseBasisRef) -> String {
    match basis_ref {
        LeaseBasisRef::Seal(seal) => seal.as_str().to_owned(),
        LeaseBasisRef::Joined(basis) => basis.control_event_set_root.as_str().to_owned(),
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
    sign_lease_fields(
        state,
        event.actor_id.clone(),
        arkret_identifiers::DeviceId::new(session.device_id.clone()).map_err(|error| {
            AppError::new(
                ErrorCode::PolicyViolation,
                format!("session device id is invalid: {error}"),
            )
            .with_status(StatusCode::FORBIDDEN)
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
    actor_id: arkret_wire::Did,
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
            AppError::new(
                ErrorCode::InternalError,
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
        alg: "EdDSA".to_owned(),
        verification_method: arkret_wire::DidUrl::new(format!("{}#notary-key", state.service_id()))
            .map_err(lease_internal_error)?,
        payload_digest: digest,
        created_at: issued_at,
        domain: None,
        audience: Some(Audience::Single(state.service_id().clone())),
        proof_purpose: None,
        jws: String::new(),
    };
    let binding = lease
        .proof_binding_bytes(&proof)
        .map_err(lease_internal_error)?;
    proof.jws =
        arkret_signatures::jws::sign_jws_ed25519(&binding, state.notary_signing_key().as_ref())
            .map_err(|error| {
                AppError::new(
                    ErrorCode::InternalError,
                    format!("authorization lease signing failed: {error}"),
                )
            })?;
    lease.proofs = vec![proof];
    lease.validate_structural().map_err(lease_internal_error)?;
    Ok(lease)
}

fn lease_internal_error(error: impl std::fmt::Display) -> AppError {
    AppError::new(
        ErrorCode::InternalError,
        format!("minted authorization lease is invalid: {error}"),
    )
}

#[cfg(test)]
mod tests {
    use arkret_wire::{Did, Event, EventKind, Hlc, RealmId, ScopeRef};
    use serde_json::json;

    use super::*;

    const REALM: &str = "ak:realm:019fbb72-ef34-76b2-bdc4-d9e31e134e89";
    const ACTOR: &str = "did:web:alice.local.host";
    const REGISTRY_DIGEST: &str =
        "sha256:9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a";

    fn event(kind: &str, actor_seq: u64, payload: Value) -> Event {
        Event::new_at(
            kind,
            ScopeRef::Realm {
                realm_id: RealmId::new(REALM).expect("fixture Realm id"),
            },
            Did::new(ACTOR).expect("fixture actor DID"),
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
            EventKind::REALM_CREATE,
            0,
            json!({"object": {
                "created_by": ACTOR,
                "capability_action_registry_digest": REGISTRY_DIGEST
            }}),
        );
        let mut followup = event(
            EventKind::REALM_HISTORY_SHARING_POLICY,
            1,
            json!({"value": {"version": 1}}),
        );
        followup.prev_refs = vec![create.event_id.clone()];
        followup.authorization_ref = Some(
            arkret_wire::AuthorizationRef::new(arkret_wire::REALM_AUTHORITY_ROOT_CELL).unwrap(),
        );

        let context = anchor_context(&[create, followup])
            .expect("ordinary Realm anchor unit is valid")
            .expect("ordinary Realm anchor unit has a lease context");
        let root = context
            .bootstrap_context
            .authority_root
            .expect("staged authority root must survive lease pre-admission");

        assert!(root.is_genesis_for(ACTOR));
        assert_eq!(
            root.capability_action_registry_digest.as_str(),
            REGISTRY_DIGEST
        );
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
        assert_eq!(error.status, Some(StatusCode::CONFLICT));
        assert_eq!(
            error.reason_code.as_deref(),
            Some(arkret_wire::ReasonCode::MLS_GOVERNANCE_BINDING_STALE)
        );
    }
}
