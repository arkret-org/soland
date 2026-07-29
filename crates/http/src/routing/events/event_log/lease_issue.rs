//! Authority-issued publication leases for final, signed Events.
//!
//! Issuance is a read-only pre-admission pass. It neither stores an Event nor
//! reserves a frontier; the later `events.submit` revalidates everything.

use arkret_wire::offline_publication::{
    AUTHORITY_SET_POLICY_SCHEMA, AnchorUnitLeaseBasis, AnchorUnitLeaseBasisRef,
    AuthoritySetAuthorizationRule, AuthoritySetIssuer, AuthoritySetIssuerRole, AuthoritySetPolicy,
    AuthoritySetPolicyKind, AuthoritySetPolicySource, AuthoritySetRef, AuthoritySetSourceKind,
    AuthorizationLease, LeaseBasisRef, RiskTier,
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
    if request.events.is_empty() || request.events.len() > MAX_EVENT_SUBMIT_BATCH {
        return Err(AppError::new(
            ErrorCode::SchemaViolation,
            format!("authorization lease issuance requires 1..={MAX_EVENT_SUBMIT_BATCH} Events"),
        )
        .with_status(StatusCode::BAD_REQUEST));
    }

    let context = anchor_context(&request.events)?;
    let bootstrap_contexts = context
        .as_ref()
        .map(|value| vec![value.bootstrap_context.clone()])
        .unwrap_or_default();
    for event in &request.events {
        let envelope = serde_json::to_value(event).map_err(|error| {
            AppError::new(
                ErrorCode::SchemaViolation,
                format!("authorization lease Event cannot be encoded: {error}"),
            )
            .with_status(StatusCode::BAD_REQUEST)
        })?;
        validate_event_envelope_with_context(state, &session, &envelope, &bootstrap_contexts, None)
            .await
            .map_err(|error| {
                AppError::new(ErrorCode::PolicyViolation, error.message).with_status(error.status)
            })?;
    }

    let anchor_basis = context.map(|value| value.basis);
    let issued_at = now();
    let expires_at = issued_at + chrono::Duration::minutes(LEASE_TTL_MINUTES);
    let mut leases = Vec::with_capacity(request.events.len());
    for event in &request.events {
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
            &session,
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

struct AnchorIssueContext {
    bootstrap_context: RealmBootstrapBatchContext,
    basis: AnchorUnitLeaseBasis,
}

fn anchor_context(events: &[Event]) -> Result<Option<AnchorIssueContext>, AppError> {
    if events
        .first()
        .is_none_or(|event| event.kind.as_str() != arkret_wire::events::EventKind::REALM_CREATE)
    {
        return Ok(None);
    }
    let (realm_id, actor_id, self_principal_pcr_bootstrap, ordinary_realm_bootstrap) =
        if events.len() == 2
            && events.get(1).is_some_and(|event| {
                event.kind.as_str() == arkret_wire::events::EventKind::DEVICE_AUTHORIZE
            })
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
                false,
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
                false,
            )
        } else {
            let unit = arkret_policy::realm_bootstrap::validate_realm_bootstrap_unit(events)
                .map_err(|error| {
                    AppError::new(
                        ErrorCode::SchemaViolation,
                        format!("invalid Realm anchor unit: {error}"),
                    )
                    .with_status(StatusCode::BAD_REQUEST)
                })?;
            (unit.realm_id, unit.actor_id, false, true)
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
            ordinary_realm_bootstrap,
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
        schema: AUTHORITY_SET_POLICY_SCHEMA.to_owned(),
        authority_set_id: "ak.authority_set.realm_admission.v1".to_owned(),
        policy_kind: AuthoritySetPolicyKind::RealmAdmission,
        scope_ref: event.scope_ref.clone(),
        source: AuthoritySetPolicySource {
            source_kind: AuthoritySetSourceKind::RealmControl,
            source_ref: format!("basis:{}", source_digest.as_str()),
            source_digest,
            generation_ref: format!("basis:{}", basis_generation_ref(basis_ref)),
        },
        authorization_rules: vec![AuthoritySetAuthorizationRule {
            rule_id: "realm_admission".to_owned(),
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
        actor_id: event.actor_id.clone(),
        device_id: arkret_identifiers::DeviceId::new(session.device_id.clone()).map_err(
            |error| {
                AppError::new(
                    ErrorCode::PolicyViolation,
                    format!("session device id is invalid: {error}"),
                )
                .with_status(StatusCode::FORBIDDEN)
            },
        )?,
        scope_ref: event.scope_ref.clone(),
        action,
        authorization_rule_id: "realm_admission".to_owned(),
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
        verification_method: format!("{}#notary-key", state.service_id()),
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
