use sha2::{Digest as _, Sha256};
use soland_services::identity::RecoverySessionState as RecoverySessionServiceState;

use super::*;

const RECOVERY_SESSION_TTL_SECS: i64 = 900;

fn generate_recovery_challenge() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
}

/// SOL-SEC-05 — constant-time string equality for recovery
/// challenge/commitment comparisons, so a timing side channel cannot leak how
/// many leading bytes of a security-relevant value matched.
fn constant_time_str_eq(left: &str, right: &str) -> bool {
    use subtle::ConstantTimeEq as _;
    let left = left.as_bytes();
    let right = right.as_bytes();
    left.len() == right.len() && bool::from(left.ct_eq(right))
}

// ── C-P2 (REC-1) recovery session lifecycle ──────────────────────────────
//
// A recovery session binds a *requesting device* to the principal's currently
// accepted recovery policy snapshot + a server-issued anti-replay challenge,
// and advances `pending -> verified` (or `rejected` / `expired`).
//
//   POST recovery-sessions                  — create (snapshot policy + challenge)
//   GET  recovery-sessions/{id}             — read status (principal-isolated)
//   POST recovery-sessions/{id}/proofs      — verify a proof (pending -> verified)
//
// C-P3 — `/proofs` cryptographically verifies did_root, recovery_unlock, and
// trusted_recovery_service over the canonical recovery-proof transcript and
// advances `pending -> verified` ONLY on success. Policy-permitted
// device_quorum and threshold_recovery currently return 501
// `recovery_proof_kind_unimplemented` rather than silently leaving the session
// pending.
//
// Completion is exclusively owned by the bound RecoveryTransaction. There is
// no second public recovery-session completion command.

/// Derive the `proof_summary{kind, proof_digest, verification_method}` from a
/// session that has a recorded proof. `proof_digest` is the SHA-256 of the
/// canonical recovery-proof transcript, deterministically recomputed from the
/// stored session fields (no separate column needed).
pub(super) fn recovery_proof_summary(record: &RecoverySessionServiceState) -> Option<ProofSummary> {
    let proof = record.proof_payload.as_ref()?.get("proof")?.as_object()?;
    let kind = match proof.get("kind").and_then(Value::as_str)? {
        "did_root" => RecoveryProofKind::DidRoot,
        "recovery_unlock" => RecoveryProofKind::RecoveryUnlock,
        "device_quorum" => RecoveryProofKind::DeviceQuorum,
        "trusted_recovery_service" => RecoveryProofKind::TrustedRecoveryService,
        "threshold_recovery" => RecoveryProofKind::ThresholdRecovery,
        _ => return None,
    };
    let verification_method = proof
        .get("verification_method")
        .and_then(Value::as_str)
        .map(DidUrl::new)
        .transpose()
        .ok()?;
    let transcript = recovery_proof_summary_transcript(record, proof)?;
    let transcript_bytes = arkret_canonical::canonical_json_bytes(&transcript).ok()?;
    let proof_digest = Hash::new(arkret_canonical::sha256_digest(&transcript_bytes)).ok()?;
    Some(ProofSummary {
        kind,
        proof_digest,
        verification_method,
    })
}

fn recovery_proof_summary_transcript(
    record: &RecoverySessionServiceState,
    proof: &Map<String, Value>,
) -> Option<Value> {
    let kind = proof.get("kind").and_then(Value::as_str)?;
    match kind {
        "trusted_recovery_service" => {
            let proof_body = trusted_recovery_service_proof_body(proof).ok()?;
            let transcript = generic_recovery_proof_transcript(
                record,
                GenericRecoveryProofBody::TrustedRecoveryService(proof_body),
            )
            .ok()?;
            serde_json::to_value(transcript).ok()
        }
        "recovery_unlock" => {
            let proof = serde_json::from_value::<arkret_models_crypto::RecoverySessionUnlockProof>(
                Value::Object(proof.clone()),
            )
            .ok()?;
            let proof_body = proof.signature_independent_proof_body().ok()?;
            let transcript = generic_recovery_proof_transcript(
                record,
                GenericRecoveryProofBody::RecoveryUnlock(proof_body),
            )
            .ok()?;
            serde_json::to_value(transcript).ok()
        }
        "did_root" => serde_json::to_value(did_root_recovery_proof_transcript(record).ok()?).ok(),
        _ => None,
    }
}

#[derive(Clone)]
struct RecoveryTranscriptContext {
    request_id: RequestId,
    session_grant_id: SessionGrantId,
    session_grant_cnf_jkt: String,
    account_id: AccountId,
    requesting_device_id: DeviceId,
    trust_domain: TrustDomainId,
    policy_id: PolicyId,
    policy_version: u64,
    recovery_session_id: RecoverySessionId,
    identity_model: RecoveryIdentityModel,
    model_generation_ref: u64,
    publication_authority_context_digest: Hash,
    challenge: Challenge,
    expires_at: chrono::DateTime<chrono::Utc>,
    created_at: chrono::DateTime<chrono::Utc>,
}

fn typed_recovery_transcript_context(
    record: &RecoverySessionServiceState,
) -> Result<RecoveryTranscriptContext, AppError> {
    Ok(RecoveryTranscriptContext {
        request_id: RequestId::new(record.request_id.clone())
            .map_err(|error| stored_recovery_type_error("request_id", error))?,
        session_grant_id: SessionGrantId::new(record.session_grant_id.clone())
            .map_err(|error| stored_recovery_type_error("session_grant_id", error))?,
        session_grant_cnf_jkt: record.session_grant_cnf_jkt.clone(),
        account_id: AccountId::new(record.principal_id.clone(), record.station_id.clone()),
        requesting_device_id: DeviceId::new(record.requesting_device_id.clone())
            .map_err(|error| stored_recovery_type_error("requesting_device_id", error))?,
        trust_domain: TrustDomainId::new(record.trust_domain.clone())
            .map_err(|error| stored_recovery_type_error("trust_domain", error))?,
        policy_id: PolicyId::new(record.policy_id.clone())
            .map_err(|error| stored_recovery_type_error("policy_id", error))?,
        policy_version: u64::from(record.policy_version),
        recovery_session_id: RecoverySessionId::new(record.recovery_session_id.clone())
            .map_err(|error| stored_recovery_type_error("recovery_session_id", error))?,
        identity_model: record.identity_model,
        model_generation_ref: record.current_device_generation_ref,
        publication_authority_context_digest: record.publication_authority_context_digest.clone(),
        challenge: Challenge::new(record.challenge.clone())
            .map_err(|error| stored_recovery_type_error("challenge", error))?,
        expires_at: record.expires_at,
        created_at: record.created_at,
    })
}

pub(super) fn typed_recovery_session_state(
    record: &RecoverySessionServiceState,
) -> Result<RecoverySessionState, AppError> {
    let transcript = typed_recovery_transcript_context(record)?;
    let state = RecoverySessionState {
        schema: SchemaId::RECOVERY_SESSION_V1.to_owned(),
        request_id: transcript.request_id,
        recovery_session_id: transcript.recovery_session_id,
        session_grant_id: transcript.session_grant_id,
        session_grant_cnf_jkt: transcript.session_grant_cnf_jkt,
        account_id: transcript.account_id,
        requesting_device_id: transcript.requesting_device_id,
        trust_domain: transcript.trust_domain,
        policy_id: transcript.policy_id,
        policy_version: transcript.policy_version,
        identity_model: transcript.identity_model,
        current_device_generation_ref: transcript.model_generation_ref,
        device_generation_status: record.device_generation_status,
        registry_head: record.registry_head.clone(),
        accepted_seal_frontier: record.accepted_seal_frontier.clone(),
        publication_authority_context: record.publication_authority_context.clone(),
        publication_authority_context_digest: record.publication_authority_context_digest.clone(),
        challenge: Challenge::new(record.challenge.clone())
            .map_err(|error| stored_recovery_type_error("challenge", error))?,
        state: record.state,
        proof_summary: recovery_proof_summary(record),
        transaction_id: record
            .transaction_id
            .as_ref()
            .map(|value| TransactionId::new(value.clone()))
            .transpose()
            .map_err(|error| stored_recovery_type_error("transaction_id", error))?,
        rejection_reason_code: None,
        expires_at: record.expires_at,
        created_at: record.created_at,
        updated_at: record.updated_at,
    };
    state
        .validate()
        .map_err(|error| stored_recovery_type_error("session state", error))?;
    Ok(state)
}

/// Snake_case wire name of a session state for diagnostics; the canonical SDK
/// [`SessionState`] enum has no `Display` impl.
fn session_state_label(state: SessionState) -> &'static str {
    match state {
        SessionState::Pending => "pending",
        SessionState::Verified => "verified",
        SessionState::Completed => "completed",
        SessionState::Rejected => "rejected",
        SessionState::Expired => "expired",
    }
}

fn recovery_policy_basis_leaves(
    basis: &LeaseBasisRef,
) -> Result<Vec<arkret_identifiers::SealId>, AppError> {
    match basis {
        LeaseBasisRef::Seal(seal_id) => Ok(vec![seal_id.clone()]),
        LeaseBasisRef::Joined(basis) => Ok(basis.leaves.clone()),
        LeaseBasisRef::AnchorUnit(_) => Err(AppError::conflict(
            "recovery policy authority cannot use a bootstrap anchor-unit basis",
        )
        .with_internal_reason("recovery_publication_authority_invalid")),
    }
}

async fn verify_device_quorum_rule_at_policy_basis(
    state: &AppState,
    active: &RecoveryPolicyState,
    policy: &RecoveryPolicy,
) -> Result<(), AppError> {
    let Some(quorum) = policy.device_quorum.as_ref() else {
        return Ok(());
    };
    let rule = policy
        .publication_authorization_rules
        .iter()
        .find(|rule| rule.proof_kind == RecoveryProofKind::DeviceQuorum)
        .ok_or_else(|| {
            AppError::conflict("device quorum policy has no publication authorization rule")
                .with_internal_reason("recovery_publication_authority_invalid")
        })?;
    let expected_methods = quorum
        .member_ids
        .iter()
        .map(|device_id| format!("{}#{}", active.account_id.principal_id, device_id))
        .collect::<BTreeSet<_>>();
    let declared_methods = rule
        .issuers
        .iter()
        .map(|issuer| issuer.verification_method.to_string())
        .collect::<BTreeSet<_>>();
    if expected_methods != declared_methods {
        return Err(AppError::conflict(
            "device quorum publication issuers do not match the policy member devices",
        )
        .with_internal_reason("recovery_publication_authority_invalid"));
    }

    let leaves = recovery_policy_basis_leaves(&active.acceptance_basis)?;
    let covered = state
        .projections()
        .seal_leaf_union_proof(&leaves)
        .await
        .map_err(|error| {
            AppError::conflict(format!(
                "recovery policy acceptance basis cannot be resolved: {error}"
            ))
            .with_internal_reason("recovery_publication_authority_invalid")
        })?
        .into_iter()
        .flat_map(|proof| proof.covered_event_digests)
        .map(|digest| digest.to_string())
        .collect::<BTreeSet<_>>();
    let events = state
        .event_queries()
        .accepted_events_for_actor(active.account_id.principal_id.as_str())
        .await
        .map_err(recovery_service_error)?;
    for member in &quorum.member_ids {
        let member = member.as_str();
        let latest_authorize = events
            .iter()
            .filter(|event| {
                covered.contains(&event.canonical_digest)
                    && event.kind == arkret_wire::EventKind::DeviceAuthorize.as_str()
                    && event.envelope["payload"]["device_id"].as_str() == Some(member)
            })
            .map(|event| event.actor_seq)
            .max();
        let latest_revoke = events
            .iter()
            .filter(|event| {
                covered.contains(&event.canonical_digest)
                    && event.kind == arkret_wire::EventKind::DeviceRevoke.as_str()
                    && event.envelope["payload"]["device_id"].as_str() == Some(member)
            })
            .map(|event| event.actor_seq)
            .max();
        if latest_authorize.is_none()
            || latest_revoke.is_some_and(|revoke| Some(revoke) >= latest_authorize)
        {
            return Err(AppError::conflict(format!(
                "device quorum member `{member}` was not active at policy acceptance basis"
            ))
            .with_internal_reason("recovery_publication_authority_invalid"));
        }
    }
    Ok(())
}

async fn pcr_policy_recovery_publication_authority_context(
    state: &AppState,
    active: &RecoveryPolicyState,
    realm_id: &RealmId,
) -> Result<RecoveryPublicationAuthorityContext, AppError> {
    let policy: RecoveryPolicy =
        serde_json::from_value(active.raw_payload.clone()).map_err(|error| {
            AppError::internal(format!("stored recovery policy is invalid: {error}"))
        })?;
    policy.validate().map_err(|error| {
        AppError::conflict(format!(
            "stored recovery policy cannot define publication authority: {error}"
        ))
        .with_internal_reason("recovery_publication_authority_invalid")
    })?;
    verify_device_quorum_rule_at_policy_basis(state, active, &policy).await?;

    let authority_set_policy = AuthoritySetPolicy {
        schema: SchemaId::AUTHORITY_SET_POLICY_V1.to_owned(),
        authority_set_id: RECOVERY_IDENTITY_REANCHOR_AUTHORITY_SET_ID.to_owned(),
        policy_kind: AuthoritySetPolicyKind::PrincipalControl,
        scope_ref: arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        source: AuthoritySetPolicySource {
            source_kind: AuthoritySetSourceKind::RecoveryPolicy,
            source_ref: active.policy_id.clone(),
            source_digest: Hash::new(arkret_canonical::canonical_sha256(&policy).map_err(
                |error| AppError::internal(format!("recovery policy digest failed: {error}")),
            )?)
            .map_err(|error| AppError::internal(format!("recovery policy digest: {error}")))?,
            generation_ref: active.version.to_string(),
        },
        authorization_rules: policy
            .publication_authorization_rules
            .iter()
            .map(|rule| AuthoritySetAuthorizationRule {
                rule_id: rule.rule_id.clone(),
                issuer_role: rule.issuer_role,
                allowed_actions: rule.allowed_actions.clone(),
                issuers: rule.issuers.clone(),
                threshold: rule.threshold,
            })
            .collect(),
    };
    let authority_set_ref = AuthoritySetRef {
        authority_set_id: RECOVERY_IDENTITY_REANCHOR_AUTHORITY_SET_ID.to_owned(),
        authority_set_digest: authority_set_policy.digest().map_err(|error| {
            AppError::internal(format!("recovery authority policy digest failed: {error}"))
        })?,
    };
    let context = RecoveryPublicationAuthorityContext {
        identity_model: RecoveryIdentityModel::PcrPolicy,
        basis_ref: active.acceptance_basis.clone(),
        scope_ref: authority_set_policy.scope_ref.clone(),
        authority_set_ref,
        authority_set_policy,
        allowed_actions: vec![RecoveryPublicationAction::DeviceReanchor],
    };
    context
        .validate_for(RecoveryIdentityModel::PcrPolicy)
        .map_err(|error| {
            AppError::conflict(format!(
                "recovery publication authority context is invalid: {error}"
            ))
            .with_internal_reason("recovery_publication_authority_invalid")
        })?;
    Ok(context)
}

/// Load a session and enforce principal isolation: only the authenticated
/// principal (== `session.actor`) may read or act on its own recovery sessions.
pub(super) async fn load_owned_recovery_session(
    aa: &AuthArgs,
    state: &AppState,
    req: &mut Request,
    recovery_session_id: &str,
) -> Result<RecoverySessionServiceState, AppError> {
    let session = aa.authenticated_session(state, req).await?;
    let (grant_id, grant_jkt, candidate_device_id) = recovery_grant_coordinates(&session)?;
    let principal = session.actor;
    let record = state
        .recovery_sessions()
        .session(recovery_session_id)
        .await
        .map_err(recovery_service_error)?
        .ok_or_else(|| {
            AppError::not_found(format!(
                "recovery session `{recovery_session_id}` not found"
            ))
        })?;
    if record.principal_id.as_str() != principal
        || record.station_id.as_str() != session.audience
        || record.requesting_device_id != candidate_device_id
        || record.session_grant_id != grant_id
        || record.session_grant_cnf_jkt != grant_jkt
    {
        return Err(crate::app_error!(
            CapabilityDenied,
            "recovery session belongs to a different principal",
        )
        .with_reason_code("recovery_principal_isolation"));
    }
    Ok(record)
}

fn recovery_grant_coordinates(
    session: &SessionRecord,
) -> Result<(String, String, String), AppError> {
    let grant = session.session_grant.as_ref().ok_or_else(|| {
        AppError::unauthenticated("recovery operation requires a recovery_session SessionGrant")
    })?;
    if grant.credential_class
        != arkret_models_identity::SessionGrantCredentialClass::RecoverySession
        || grant.device_binding.is_some()
    {
        return Err(crate::app_error!(
            CapabilityDenied,
            "recovery operation requires a restricted recovery_session grant",
        ));
    }
    let arkret_models_identity::SessionGrantHolderBinding::RecoveryCandidateDevice { device_id } =
        &grant.holder_binding
    else {
        return Err(AppError::unauthenticated(
            "recovery session grant has the wrong holder binding",
        ));
    };
    if device_id.as_str() != session.device_id {
        return Err(AppError::unauthenticated(
            "recovery candidate device does not match the authenticated session",
        ));
    }
    Ok((
        grant.grant_id.to_string(),
        grant.cnf_jkt.clone(),
        device_id.to_string(),
    ))
}

#[salvo::oapi::endpoint(
    operation_id = "ak.root.identity.recovery_session.command.create",
    tags("identity")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.root.identity.recovery_session.command.create.v1")
)]
pub(super) async fn recovery_session_create(
    aa: AuthArgs,
    body: JsonBody<RecoverySessionCreateRequestBody>,
    depot: &mut Depot,
    res: &mut Response,
    req: &mut Request,
) -> JsonResult<RecoverySessionState> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let (session_grant_id, session_grant_cnf_jkt, candidate_device_id) =
        recovery_grant_coordinates(&session)?;
    let principal = session.actor.clone();
    let payload = body.into_inner();
    let create_intent_digest = Hash::new(arkret_canonical::canonical_sha256(&payload).map_err(
        |error| AppError::internal(format!("recovery create canonicalization failed: {error}")),
    )?)
    .map_err(|error| AppError::internal(format!("recovery create digest failed: {error}")))?;
    if payload.requesting_device_id.as_str() != candidate_device_id {
        return Err(crate::app_error!(
            CapabilityDenied,
            "requesting_device_id does not match the recovery grant holder",
        )
        .with_reason_code("recovery_evidence_unbound"));
    }
    if let Some(existing) = state
        .recovery_sessions()
        .session_for_request(&session_grant_id, payload.request_id.as_str())
        .await
        .map_err(recovery_session_store_error)?
    {
        if existing.create_intent_digest == create_intent_digest.as_str() {
            return json_ok(typed_recovery_session_state(&existing)?);
        }
        return Err(AppError::conflict(
            "recovery request_id was already used with a different create intent",
        )
        .with_wire_code("duplicate_conflict"));
    }
    if state
        .recovery_sessions()
        .session_for_grant(&session_grant_id)
        .await
        .map_err(recovery_session_store_error)?
        .is_some()
    {
        return Err(AppError::conflict(
            "recovery SessionGrant is already bound to another recovery session",
        )
        .with_wire_code("duplicate_conflict"));
    }

    let account_id = payload.account_id;
    if account_id.principal_id.as_str() != principal {
        return Err(crate::app_error!(
            CapabilityDenied,
            "account_id.principal_id does not match the authenticated principal",
        )
        .with_reason_code("recovery_principal_isolation"));
    }
    if account_id.station_id.as_str() != state.service_id() {
        return Err(
            crate::app_error!(FailedPrecondition, "account_id does not bind this Station",)
                .with_internal_reason("account_id_mismatch"),
        );
    }
    let authority_record = state
        .persistence()
        .principal_resolution_by_account_id(&account_id)
        .await
        .map_err(|error| AppError::internal(format!("principal authority lookup failed: {error}")))?
        .ok_or_else(|| {
            crate::app_error!(
                FailedPrecondition,
                "principal authority is not accepted by this Station",
            )
            .with_internal_reason("account_id_mismatch")
        })?;
    let requesting_device_id = payload.requesting_device_id.as_str().to_owned();
    if !requesting_device_id.starts_with("ak:device:") {
        return Err(AppError::param_invalid(format!(
            "requesting_device_id `{requesting_device_id}` must start with ak:device:",
        )));
    }
    let trust_domain = payload.trust_domain.as_str().to_owned();
    if !trust_domain.starts_with("ak:trust_domain:") {
        return Err(AppError::param_invalid(format!(
            "trust_domain `{trust_domain}` must start with ak:trust_domain:",
        )));
    }
    // A session can only be opened against an accepted recovery policy — and the
    // requested trust_domain MUST match it (no domain confusion).
    let active = state
        .recovery_policies()
        .active_policy(&account_id)
        .await
        .map_err(recovery_service_error)?
        .ok_or_else(|| {
            AppError::conflict(format!(
                "no accepted recovery policy for principal `{principal}`"
            ))
            .with_wire_code("recovery_policy_mismatch")
        })?;
    if active.trust_domain != trust_domain {
        return Err(AppError::conflict(format!(
            "trust_domain `{trust_domain}` does not match active policy `{}`",
            active.trust_domain
        ))
        .with_wire_code("recovery_policy_trust_domain_mismatch"));
    }
    if active.allowed_proof_kinds.is_empty() {
        // An explicit-revocation policy (allowed_proof_kinds == []) cannot back a
        // recovery session — there is no proof the requester_id could ever satisfy.
        return Err(AppError::conflict(format!(
            "active recovery policy `{}` permits no proof kinds (recovery disabled)",
            active.policy_id
        ))
        .with_wire_code("recovery_policy_revoked"));
    }

    // Optional client CAS hint: if `expected_recovery_policy_ref` is present it
    // MUST match the policy the server is about to snapshot, else the client is
    // racing a policy rotation → recovery_policy_mismatch.
    if let Some(expected) = payload.expected_recovery_policy_ref.as_ref()
        && (expected.policy_id.as_str() != active.policy_id
            || expected.policy_version != active.version as u64)
    {
        return Err(AppError::conflict(format!(
            "expected_recovery_policy_ref does not match active policy `{}` v{}",
            active.policy_id, active.version
        ))
        .with_wire_code("recovery_policy_mismatch"));
    }

    let device_generation =
        crate::routing::identity::device_generation::current_device_generation(state, &principal)
            .await
            .map_err(recovery_store_error)?;
    let realm_id = authority_record.pcr_realm_id;
    let (
        identity_model,
        current_device_generation_ref,
        device_generation_status,
        registry_head,
        accepted_seal_frontier,
    ) = if let Some(generation) = device_generation {
        let mut entries = state
            .dids()
            .log_events(&principal)
            .await
            .map_err(recovery_service_error)?;
        entries.sort_by_key(|entry| entry.seq);
        let registry_head = entries
            .last()
            .map(|entry| entry.event_digest.clone())
            .ok_or_else(|| {
                AppError::conflict("recovery requires an accepted DID registry head")
                    .with_wire_code("device_reanchor_entry_not_head")
            })?;
        let leaves =
            crate::routing::identity::device_generation::accepted_device_generation_seal_leaves(
                state, &principal, &realm_id,
            )
            .await
            .map_err(recovery_store_error)?;
        if leaves.is_empty() {
            return Err(
                AppError::conflict("recovery requires a non-empty accepted Seal frontier")
                    .with_wire_code("device_reanchor_frontier_mismatch"),
            );
        }
        let view = state
            .projections()
            .effective_seal_view(&leaves, &realm_id)
            .await
            .map_err(|error| {
                AppError::conflict(format!("accepted Seal frontier is invalid: {error}"))
                    .with_wire_code("device_reanchor_frontier_mismatch")
            })?;
        let accepted_seal_frontier = arkret_wire::DeviceReanchorPreFenceSealFrontier {
            leaves,
            control_event_set_root: view.control_event_set_root,
            state_root: view.state_root,
        };
        (
            RecoveryIdentityModel::PcrPolicy,
            generation.current_ref,
            match generation.status {
                crate::routing::identity::device_generation::DeviceGenerationStatus::Active => {
                    DeviceGenerationStatus::Active
                }
                crate::routing::identity::device_generation::DeviceGenerationStatus::Conflicted => {
                    DeviceGenerationStatus::Conflicted
                }
            },
            Hash::new(registry_head).map_err(|error| {
                AppError::internal(format!("invalid accepted DID registry head: {error}"))
            })?,
            accepted_seal_frontier,
        )
    } else {
        return Err(
            AppError::conflict("recovery requires an accepted device generation")
                .with_internal_reason("device_generation_missing"),
        );
    };

    let publication_authority_context =
        pcr_policy_recovery_publication_authority_context(state, &active, &realm_id).await?;
    let publication_authority_context_digest =
        publication_authority_context.digest().map_err(|error| {
            AppError::internal(format!(
                "recovery publication authority context digest failed: {error}"
            ))
        })?;
    let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let record = RecoverySessionServiceState {
        request_id: payload.request_id.to_string(),
        create_intent_digest: create_intent_digest.to_string(),
        recovery_session_id: crate::ids::generate("recovery_session"),
        session_grant_id,
        session_grant_cnf_jkt,
        principal_id: account_id.principal_id.clone(),
        station_id: account_id.station_id.clone(),
        requesting_device_id,
        trust_domain,
        policy_id: active.policy_id.clone(),
        policy_version: active.version,
        identity_model,
        current_device_generation_ref,
        device_generation_status,
        registry_head,
        accepted_seal_frontier,
        policy_payload: active.raw_payload.clone(),
        publication_authority_context,
        publication_authority_context_digest,
        challenge: generate_recovery_challenge(),
        state: SessionState::Pending,
        proof_payload: None,
        transaction_id: None,
        created_at: now,
        updated_at: now,
        expires_at: (now + chrono::Duration::seconds(RECOVERY_SESSION_TTL_SECS))
            .min(session.expires_at),
    };
    if let Err(error) = state
        .recovery_sessions()
        .create_session(record.clone())
        .await
    {
        if error.conflict_code() == Some(soland_storage::ConflictCode::RecoverySessionAlreadyExists)
        {
            if let Some(existing) = state
                .recovery_sessions()
                .session_for_request(&record.session_grant_id, record.request_id.as_str())
                .await
                .map_err(recovery_session_store_error)?
            {
                if existing.create_intent_digest == record.create_intent_digest {
                    return json_ok(typed_recovery_session_state(&existing)?);
                }
                return Err(AppError::conflict(
                    "recovery request_id was concurrently used with a different create intent",
                )
                .with_wire_code("duplicate_conflict"));
            }
            if state
                .recovery_sessions()
                .session_for_grant(&record.session_grant_id)
                .await
                .map_err(recovery_session_store_error)?
                .is_some()
            {
                return Err(AppError::conflict(
                    "recovery SessionGrant was concurrently bound to another recovery session",
                )
                .with_wire_code("duplicate_conflict"));
            }
        }
        return Err(recovery_session_store_error(error));
    }

    append_audit_log(
        state,
        Some(&session.actor),
        arkret_wire::ServiceOperationId::ROOT_IDENTITY_RECOVERY_SESSION_COMMAND_CREATE_V1,
        json!({
            "recovery_session_id": record.recovery_session_id.clone(),
            "account_id": {
                "principal_id": record.principal_id.clone(),
                "station_id": record.station_id.clone(),
            },
            "policy_id": record.policy_id.clone(),
            "trust_domain": record.trust_domain.clone(),
        }),
        "created",
    )
    .await;

    res.status_code(StatusCode::CREATED);
    json_ok(typed_recovery_session_state(&record)?)
}

#[salvo::oapi::endpoint(
    operation_id = "ak.root.identity.recovery_session.resource.get",
    tags("identity")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.root.identity.recovery_session.resource.get.v1")
)]
pub(super) async fn recovery_session_get(
    aa: AuthArgs,
    recovery_session_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RecoverySessionState> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let mut record =
        load_owned_recovery_session(&aa, state, req, &recovery_session_id.into_inner()).await?;
    record = expire_if_elapsed(state, record).await?;
    json_ok(typed_recovery_session_state(&record)?)
}

#[salvo::oapi::endpoint(
    operation_id = "ak.root.identity.recovery_session.command.submit_proof",
    tags("identity")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.root.identity.recovery_session.command.submit_proof.v1")
)]
pub(super) async fn recovery_session_proof_submit(
    aa: AuthArgs,
    recovery_session_id: PathParam<String>,
    body: JsonBody<RecoverySessionProofSubmitRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RecoverySessionProofSubmitOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session_id = recovery_session_id.into_inner();
    let record = load_owned_recovery_session(&aa, state, req, &session_id).await?;
    let record = expire_if_elapsed(state, record).await?;
    if record.state != SessionState::Pending {
        return Err(AppError::conflict(format!(
            "recovery session is `{}`, proofs accepted only while `pending`",
            session_state_label(record.state)
        ))
        .with_wire_code("recovery_session_not_pending"));
    }

    let payload = body.into_inner();
    let payload_value = serde_json::to_value(&payload)
        .map_err(|error| AppError::internal(format!("recovery proof submit serialize: {error}")))?;
    let proof = payload_value
        .get("proof")
        .ok_or_else(|| AppError::param_invalid("proof object is required"))?
        .as_object()
        .ok_or_else(|| AppError::param_invalid("proof object is required"))?;
    let proof_kind = proof
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::param_invalid("proof.kind is required"))?;
    if !ALLOWED_PROOF_KINDS.contains(&proof_kind) {
        return Err(AppError::param_invalid(
            format!("proof.kind `{proof_kind}` not in spec enum",),
        )
        .with_reason_code("recovery_proof_kind_unknown"));
    }
    // The proof kind MUST be one the bound policy snapshot permits.
    let policy_allows = record
        .policy_payload
        .get("allowed_proof_kinds")
        .and_then(Value::as_array)
        .map(|kinds| kinds.iter().any(|k| k.as_str() == Some(proof_kind)))
        .unwrap_or(false);
    if !policy_allows {
        return Err(AppError::conflict(format!(
            "proof.kind `{proof_kind}` is not permitted by the bound recovery policy",
        ))
        .with_wire_code("recovery_proof_kind_not_allowed"));
    }
    // Anti-replay: the proof MUST echo the server-issued session challenge.
    let echoed = proof
        .get("challenge")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::param_invalid("proof.challenge is required"))?;
    if !constant_time_str_eq(echoed, &record.challenge) {
        return Err(crate::app_error!(
            SignatureInvalid,
            "proof.challenge does not match the session challenge",
        )
        .with_reason_code("recovery_session_challenge_mismatch"));
    }

    // C-P3 — verify the proof by kind. Only `did_root` is implemented;
    // other (policy-permitted) kinds return 501 rather than silently leaving the
    // session pending, so a caller is never misled into thinking the server
    // accepted a proof it cannot actually check.
    match proof_kind {
        "did_root" => {
            verify_did_root_proof(state, &record, proof).await?;
        }
        "recovery_unlock" => {
            verify_recovery_unlock_proof(state, &record, proof).await?;
        }
        "trusted_recovery_service" => {
            verify_trusted_recovery_service_proof(state, &record, proof).await?;
        }
        other => {
            return Err(AppError::unsupported_feature(format!(
                "proof.kind `{other}` verification not yet implemented (C-P3)"
            ))
            .with_wire_code("recovery_proof_kind_unimplemented"));
        }
    }

    // Proof verified — advance `pending -> verified` and record the proof. The
    // server only reaches this point after a real cryptographic check.
    let now = chrono::Utc::now();
    let updated = RecoverySessionServiceState {
        state: SessionState::Verified,
        proof_payload: Some(payload_value.clone()),
        updated_at: now,
        ..record
    };
    state
        .recovery_sessions()
        .save_session(updated.clone())
        .await
        .map_err(recovery_session_store_error)?;

    let proof_summary = recovery_proof_summary(&updated);
    append_audit_log(
        state,
        Some(updated.principal_id.as_str()),
        arkret_wire::ServiceOperationId::ROOT_IDENTITY_RECOVERY_SESSION_COMMAND_SUBMIT_PROOF_V1,
        json!({
            "recovery_session_id": updated.recovery_session_id.clone(),
            "principal_id": updated.principal_id.clone(),
            "policy_id": updated.policy_id.clone(),
            "trust_domain": updated.trust_domain.clone(),
            "proof_kind": proof_kind,
            "verification_method": proof
                .get("verification_method")
                .cloned()
                .unwrap_or(Value::Null),
            "service_id": proof
                .get("service_id")
                .cloned()
                .unwrap_or(Value::Null),
            "proof_summary": proof_summary,
        }),
        "verified",
    )
    .await;

    json_ok(RecoverySessionProofSubmitOutcome {
        recovery_session_id: RecoverySessionId::new(updated.recovery_session_id.clone())
            .map_err(|error| stored_recovery_type_error("recovery_session_id", error))?,
        state: updated.state,
        verification: "verified".to_owned(),
        proof_summary: recovery_proof_summary(&updated),
    })
}

/// C-P3 — verify a `did_root` recovery proof.
///
/// The proof MUST carry an Ed25519 signature by the principal's signing key
/// over the canonical recovery-proof transcript, which binds every
/// session-defining field: `(principal_id, requesting_device_id, trust_domain,
/// policy_id, policy_version, recovery_session_id, device generation, challenge,
/// created_at, expires_at)`.
/// Because the transcript is reconstructed server-side from the stored session,
/// any proof signed over a different binding (stale policy, replayed across
/// principal/domain, different session) fails verification — this gives the
/// `recovery_evidence_unbound` guarantee for free.
pub(super) async fn verify_did_root_proof(
    state: &AppState,
    record: &RecoverySessionServiceState,
    proof: &Map<String, Value>,
) -> Result<(), AppError> {
    if record.station_id.as_str() != state.service_id() {
        return Err(recovery_signature_error(
            "recovery session principal authority pair does not bind this Station",
        ));
    }
    let verification_method = required_proof_string(proof, "verification_method")?;
    let (method_did, device_fragment) = verification_method.rsplit_once('#').ok_or_else(|| {
        recovery_signature_error("did-root verification_method has no device fragment")
    })?;
    let method_did = arkret_identifiers::Did::new(method_did.to_owned()).map_err(|error| {
        recovery_signature_error(format!("did-root method DID is invalid: {error}"))
    })?;
    let method_principal = arkret_wire::project_did_to_core_id(&method_did).map_err(|error| {
        recovery_signature_error(format!("did-root method DID cannot be projected: {error}"))
    })?;
    if method_principal != record.principal_id {
        return Err(recovery_signature_error(
            "did-root method does not belong to the recovery session authority pair",
        ));
    }
    let device_id =
        arkret_identifiers::DeviceId::new(device_fragment.to_owned()).map_err(|error| {
            recovery_signature_error(format!("did-root device fragment is invalid: {error}"))
        })?;
    let authority_key =
        arkret_wire::AccountId::new(record.principal_id.clone(), record.station_id.clone());
    let authority = state
        .persistence()
        .principal_resolution_by_account_id(&authority_key)
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "recovery principal authority lookup failed: {error}"
            ))
        })?
        .ok_or_else(|| {
            recovery_signature_error("recovery principal authority pair is not durably accepted")
        })?;
    let device = state
        .identities()
        .find_device(soland_services::identity::FindDeviceQuery {
            actor_id: record.principal_id.to_string(),
            device_id: device_id.to_string(),
        })
        .await
        .map_err(|error| {
            AppError::internal(format!("recovery signing device lookup failed: {error}"))
        })?
        .ok_or_else(|| recovery_signature_error("recovery signing device is unavailable"))?;
    if device.revoked_at.is_some() || device.verification_state != "verified" {
        return Err(recovery_signature_error(
            "recovery signing device is not active",
        ));
    }
    let payload = serde_json::from_value::<
        crate::routing::identity::device_signing::ProjectedDevicePayload,
    >(device.payload)
    .map_err(|error| {
        AppError::internal(format!(
            "recovery signing device evidence is invalid: {error}"
        ))
    })?;
    let authorize_event_id = payload.device_authorize_event_id.ok_or_else(|| {
        recovery_signature_error("recovery signing device has no accepted authorization Event")
    })?;
    let authorize_event = state
        .event_queries()
        .canonical_event(authorize_event_id.as_str())
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "recovery device authorization lookup failed: {error}"
            ))
        })?
        .ok_or_else(|| {
            recovery_signature_error("recovery device authorization Event is unavailable")
        })?;
    if !authorization_event_actor_matches_account(&authorize_event.actor_id, &authority_key)
        || authorize_event.kind != arkret_wire::event_kind_str::DEVICE_AUTHORIZE
        || authorize_event.realm_id.as_deref() != Some(authority.pcr_realm_id.as_str())
    {
        return Err(recovery_signature_error(
            "recovery signing device authorization is outside the selected account lineage",
        ));
    }
    let signing_key = payload
        .device_public_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| recovery_signature_error("recovery signing device key is unavailable"))?;
    let key =
        crate::routing::identity::device_signing::decode_ed25519_key(signing_key, "multibase")
            .map_err(|error| {
                recovery_signature_error(format!("recovery signing device key is invalid: {error}"))
            })?;
    let transcript = did_root_recovery_proof_transcript(record)?;
    let transcript_bytes =
        arkret_canonical::canonical_json_bytes(&transcript).map_err(|error| {
            AppError::internal(format!("recovery proof transcript failed: {error}"))
        })?;
    let signature_b64 = required_proof_string(proof, "signature")?;
    let raw = URL_SAFE_NO_PAD
        .decode(signature_b64.as_bytes())
        .or_else(|_| STANDARD.decode(signature_b64.as_bytes()))
        .map_err(|_| recovery_signature_error("proof.signature is not base64/base64url"))?;
    let signature = Signature::from_slice(&raw)
        .map_err(|_| recovery_signature_error("proof.signature must be 64 Ed25519 bytes"))?;
    key.verify(&transcript_bytes, &signature).map_err(|_| {
        crate::metrics::record_digest_mismatch("recovery_proof_digest");
        recovery_signature_error("did-root recovery proof signature verification failed")
    })
}

pub(super) async fn verify_trusted_recovery_service_proof(
    state: &AppState,
    record: &RecoverySessionServiceState,
    proof: &Map<String, Value>,
) -> Result<(), AppError> {
    let signature_algorithm = required_proof_string(proof, "signature_algorithm")?;
    if signature_algorithm != "Ed25519" {
        return Err(AppError::param_invalid(format!(
            "proof.signature_algorithm `{signature_algorithm}` must be `Ed25519`",
        )));
    }
    let service_id = required_proof_string(proof, "service_id")?;
    let audience = required_proof_string(proof, "audience")?;
    if audience != state.service_id() {
        return Err(recovery_proof_authority_error(format!(
            "proof.audience `{audience}` does not match this service"
        )));
    }
    let verification_method = required_proof_string(proof, "verification_method")?;
    let _service_id =
        arkret_identifiers::DidCoreId::new(service_id.to_owned()).map_err(|error| {
            recovery_proof_authority_error(format!("proof.service_id is invalid: {error}"))
        })?;
    if !recovery_policy_mentions_identifier(
        &record.policy_payload,
        &[
            "trusted_recovery_service",
            "trusted_recovery_services",
            "trusted_services",
            "recovery_services",
        ],
        service_id,
    ) {
        return Err(recovery_proof_authority_error(format!(
            "proof.service_id `{service_id}` is not trusted by the bound recovery policy"
        )));
    }
    if recovery_policy_requires_trusted_service_attestation(&record.policy_payload)
        && proof
            .get("attestation_ref")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
    {
        return Err(recovery_proof_authority_error(
            "trusted recovery service proof is missing attestation_ref",
        ));
    }
    crate::jws_verify::validate_verification_method_controller(service_id, verification_method)
        .map_err(|error| {
            recovery_proof_authority_error(format!(
                "proof.verification_method authority invalid: {error}"
            ))
        })?;
    let service_key = crate::jws_verify::resolve_ed25519_pubkey_async(state, verification_method)
        .await
        .map_err(|error| {
            recovery_proof_authority_error(format!("trusted recovery service key invalid: {error}"))
        })?;
    let proof_body = trusted_recovery_service_proof_body(proof)?;
    let transcript = generic_recovery_proof_transcript(
        record,
        GenericRecoveryProofBody::TrustedRecoveryService(proof_body),
    )?;
    let transcript_bytes =
        arkret_canonical::canonical_json_bytes(&transcript).map_err(|error| {
            AppError::internal(format!("recovery proof transcript failed: {error}"))
        })?;
    let signature_b64 = required_proof_string(proof, "signature")?;
    let raw = URL_SAFE_NO_PAD
        .decode(signature_b64.as_bytes())
        .or_else(|_| STANDARD.decode(signature_b64.as_bytes()))
        .map_err(|_| recovery_signature_error("proof.signature is not base64/base64url"))?;
    let signature = Signature::from_slice(&raw)
        .map_err(|_| recovery_signature_error("proof.signature must be 64 Ed25519 bytes"))?;
    service_key
        .verify(&transcript_bytes, &signature)
        .map_err(|_| {
            crate::metrics::record_digest_mismatch("recovery_proof_digest");
            recovery_signature_error("trusted recovery service proof signature verification failed")
        })
}

/// §15 step 2 — verify a `recovery_unlock` recovery proof.
///
/// The 24-word Recovery Key (§3.3) unlock factor. Trust root is the principal's
/// own published `recovery_policy.recovery_keys[]` (not the DID document):
///
/// (a) `recovery_secret_ref` MUST resolve to a `recovery_keys[]` entry that was
///     authoritative at the session `created_at` (not_before/expires_at window,
///     not revoked), and `verification_method` MUST equal that entry's
///     verification_method;
/// (b) `signature` (under the entry's `signature_algorithm`, Ed25519) MUST verify over the
///     generic recovery transcript whose proof_body is this proof object with
///     `signature` and `unlock_commitment` removed, using the public key
///     decoded from the entry's `public_key_multibase`;
/// (c) `unlock_commitment` MUST equal
///     SHA-256(utf8("ak.recovery-session-unlock-binding-v1\n")
///       || utf8(recovery_secret_ref) || unlock_binding_input_bytes),
///     where unlock_binding_input_bytes is the same canonical transcript bytes
///     verified in (b).
pub(super) async fn verify_recovery_unlock_proof(
    _state: &AppState,
    record: &RecoverySessionServiceState,
    proof: &Map<String, Value>,
) -> Result<(), AppError> {
    let signature_algorithm = required_proof_string(proof, "signature_algorithm")?;
    if signature_algorithm != "Ed25519" {
        return Err(AppError::param_invalid(format!(
            "proof.signature_algorithm `{signature_algorithm}` must be `Ed25519` for recovery_unlock",
        )));
    }
    let recovery_secret_ref = required_proof_string(proof, "recovery_secret_ref")?;
    let verification_method = required_proof_string(proof, "verification_method")?;
    let unlock_commitment = required_proof_string(proof, "unlock_commitment")?;

    // (a) Resolve the recovery key entry from the bound recovery policy.
    let entry = resolve_recovery_key_entry(
        &record.policy_payload,
        recovery_secret_ref,
        record.created_at,
    )?;
    let entry_method = entry
        .get("verification_method")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if entry_method != recovery_secret_ref || entry_method != verification_method {
        return Err(recovery_evidence_unbound_error(
            "recovery_unlock verification_method does not match the resolved recovery key entry",
        ));
    }
    let entry_signature_algorithm = entry
        .get("signature_algorithm")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if entry_signature_algorithm != signature_algorithm {
        return Err(recovery_evidence_unbound_error(
            "recovery_unlock proof.signature_algorithm does not match the recovery key entry signature_algorithm",
        ));
    }
    let recovery_key = decode_recovery_key_public_key(&entry)?;

    // (b)/(c) Build the SDK-owned signature-independent binding transcript
    // once; both the signature and the commitment cover it.
    let typed_proof = serde_json::from_value::<arkret_models_crypto::RecoverySessionUnlockProof>(
        Value::Object(proof.clone()),
    )
    .map_err(|error| AppError::param_invalid(format!("invalid recovery_unlock proof: {error}")))?;
    let proof_body = typed_proof
        .signature_independent_proof_body()
        .map_err(|error| {
            AppError::param_invalid(format!("invalid recovery_unlock proof: {error}"))
        })?;
    let transcript = generic_recovery_proof_transcript(
        record,
        GenericRecoveryProofBody::RecoveryUnlock(proof_body),
    )?;
    let transcript_bytes =
        arkret_canonical::canonical_json_bytes(&transcript).map_err(|error| {
            AppError::internal(format!("recovery_unlock transcript failed: {error}"))
        })?;

    // (c) unlock_commitment integrity.
    let mut hasher = Sha256::new();
    hasher.update(b"ak.recovery-session-unlock-binding-v1\n");
    hasher.update(recovery_secret_ref.as_bytes());
    hasher.update(&transcript_bytes);
    let expected_commitment = format!("sha256:{}", hex::encode(hasher.finalize()));
    if !constant_time_str_eq(unlock_commitment, &expected_commitment) {
        crate::metrics::record_digest_mismatch("recovery_unlock_commitment");
        return Err(recovery_evidence_unbound_error(
            "recovery_unlock unlock_commitment does not match the recomputed binding",
        ));
    }

    // (b) signature possession proof.
    let signature_b64 = required_proof_string(proof, "signature")?;
    let raw = URL_SAFE_NO_PAD
        .decode(signature_b64.as_bytes())
        .or_else(|_| STANDARD.decode(signature_b64.as_bytes()))
        .map_err(|_| recovery_signature_error("proof.signature is not base64/base64url"))?;
    let signature = Signature::from_slice(&raw)
        .map_err(|_| recovery_signature_error("proof.signature must be 64 Ed25519 bytes"))?;
    recovery_key
        .verify(&transcript_bytes, &signature)
        .map_err(|_| {
            crate::metrics::record_digest_mismatch("recovery_proof_digest");
            recovery_signature_error("recovery_unlock proof signature verification failed")
        })
}

/// Resolve a non-revoked, in-window `recovery_keys[]` entry whose
/// `verification_method` equals `recovery_secret_ref`, evaluated at `as_of`
/// (the recovery session `created_at`).
pub(super) fn resolve_recovery_key_entry(
    policy_payload: &Value,
    recovery_secret_ref: &str,
    as_of: chrono::DateTime<chrono::Utc>,
) -> Result<Map<String, Value>, AppError> {
    let entries = policy_payload
        .get("recovery_keys")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            recovery_evidence_unbound_error(
                "bound recovery policy declares no recovery_keys[] for recovery_unlock",
            )
        })?;
    for entry in entries {
        let Some(object) = entry.as_object() else {
            continue;
        };
        if object.get("verification_method").and_then(Value::as_str) != Some(recovery_secret_ref) {
            continue;
        }
        if !recovery_key_entry_authoritative_at(object, as_of) {
            return Err(recovery_evidence_unbound_error(
                "recovery key entry is revoked or outside its validity window",
            ));
        }
        return Ok(object.clone());
    }
    Err(recovery_evidence_unbound_error(
        "recovery_secret_ref does not resolve to a recovery_keys[] entry",
    ))
}

/// `not_before <= as_of < expires_at` and (`revoked_at` is null or
/// `as_of < revoked_at`).
fn recovery_key_entry_authoritative_at(
    entry: &Map<String, Value>,
    as_of: chrono::DateTime<chrono::Utc>,
) -> bool {
    let parse = |key: &str| -> Option<chrono::DateTime<chrono::Utc>> {
        entry
            .get(key)
            .and_then(Value::as_str)
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
            .map(|value| value.with_timezone(&chrono::Utc))
    };
    let Some(not_before) = parse("not_before") else {
        return false;
    };
    let Some(expires_at) = parse("expires_at") else {
        return false;
    };
    if as_of < not_before || as_of >= expires_at {
        return false;
    }
    match entry.get("revoked_at") {
        Some(Value::Null) | None => true,
        Some(Value::String(_)) => parse("revoked_at").is_some_and(|revoked| as_of < revoked),
        _ => false,
    }
}

/// Decode the Ed25519 key material carried by the resolved, principal-signed
/// recovery-policy entry. `verification_method` is only its stable DID URL;
/// B-model principals intentionally do not need to publish this recovery-only
/// key in their DID Document.
pub(super) fn decode_recovery_key_public_key(
    entry: &Map<String, Value>,
) -> Result<VerifyingKey, AppError> {
    let multibase = entry
        .get("public_key_multibase")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            recovery_evidence_unbound_error(
                "recovery key entry does not carry public_key_multibase",
            )
        })?;
    crate::routing::identity::device_signing::decode_ed25519_key(multibase, "multibase")
        .map_err(|error| recovery_evidence_unbound_error(format!("recovery key invalid: {error}")))
}

fn required_proof_string<'a>(
    proof: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a str, AppError> {
    proof
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::param_invalid(format!("proof.{key} is required")))
}

fn trusted_recovery_service_proof_body(
    proof: &Map<String, Value>,
) -> Result<TrustedRecoveryServiceProofBody, AppError> {
    let proof =
        serde_json::from_value::<TrustedRecoveryServiceSessionProof>(Value::Object(proof.clone()))
            .map_err(|error| {
                AppError::param_invalid(format!("invalid trusted_recovery_service proof: {error}"))
            })?;
    proof.signature_independent_proof_body().map_err(|error| {
        AppError::param_invalid(format!("invalid trusted_recovery_service proof: {error}"))
    })
}

fn recovery_policy_mentions_identifier(
    policy_payload: &Value,
    top_level_keys: &[&str],
    identifier: &str,
) -> bool {
    top_level_keys.iter().any(|key| {
        policy_payload
            .get(*key)
            .is_some_and(|value| value_mentions_identifier(value, identifier))
    })
}

fn value_mentions_identifier(value: &Value, identifier: &str) -> bool {
    match value {
        Value::String(value) => value == identifier,
        Value::Array(values) => values
            .iter()
            .any(|value| value_mentions_identifier(value, identifier)),
        Value::Object(object) => object
            .values()
            .any(|value| value_mentions_identifier(value, identifier)),
        _ => false,
    }
}

fn recovery_policy_requires_trusted_service_attestation(policy_payload: &Value) -> bool {
    [
        "/trusted_recovery_service/attestation_required",
        "/trusted_recovery_services/attestation_required",
        "/proof_requirements/trusted_recovery_service/attestation_required",
        "/attestation_required",
    ]
    .iter()
    .any(|pointer| {
        policy_payload
            .pointer(pointer)
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }) || ["trusted_recovery_service", "trusted_recovery_services"]
        .iter()
        .any(|key| {
            policy_payload
                .get(*key)
                .is_some_and(value_requires_attestation)
        })
}

fn value_requires_attestation(value: &Value) -> bool {
    match value {
        Value::Object(object) => {
            object
                .get("attestation_required")
                .and_then(Value::as_bool)
                .unwrap_or(false)
                || object.values().any(value_requires_attestation)
        }
        Value::Array(values) => values.iter().any(value_requires_attestation),
        _ => false,
    }
}

fn recovery_proof_authority_error(message: impl Into<String>) -> AppError {
    crate::app_error!(SignatureInvalid, message.into())
        .with_wire_code("recovery_proof_authority_invalid")
}

/// Canonical recovery-proof transcript binding every session-defining field.
/// Both the requesting device (when signing) and the server (when verifying)
/// MUST construct this identically.
pub(super) fn did_root_recovery_proof_transcript(
    record: &RecoverySessionServiceState,
) -> Result<DidRootTranscript, AppError> {
    let context = typed_recovery_transcript_context(record)?;
    let transcript = DidRootTranscript {
        schema: arkret_wire::DomainSeparationId::IDENTITY_RECOVERY_PROOF_V1.to_owned(),
        kind: RecoveryProofKind::DidRoot,
        request_id: context.request_id,
        session_grant_id: context.session_grant_id,
        session_grant_cnf_jkt: context.session_grant_cnf_jkt,
        account_id: context.account_id,
        requesting_device_id: context.requesting_device_id,
        trust_domain: context.trust_domain,
        policy_id: context.policy_id,
        policy_version: context.policy_version,
        recovery_session_id: context.recovery_session_id,
        identity_model: context.identity_model,
        model_generation_ref: context.model_generation_ref,
        publication_authority_context_digest: context.publication_authority_context_digest,
        challenge: context.challenge,
        expires_at: context.expires_at,
        // created_at is the SESSION creation/signing time (not proof time), per
        // recovery-session.schema.json $defs/did_root_transcript.
        created_at: context.created_at,
    };
    transcript
        .validate()
        .map_err(|error| stored_recovery_type_error("did_root transcript", error))?;
    Ok(transcript)
}

pub(super) fn generic_recovery_proof_transcript(
    record: &RecoverySessionServiceState,
    proof_body: GenericRecoveryProofBody,
) -> Result<GenericRecoveryTranscript, AppError> {
    let context = typed_recovery_transcript_context(record)?;
    let transcript = GenericRecoveryTranscript {
        schema: arkret_wire::DomainSeparationId::IDENTITY_RECOVERY_PROOF_V1.to_owned(),
        kind: proof_body.kind(),
        request_id: context.request_id,
        session_grant_id: context.session_grant_id,
        session_grant_cnf_jkt: context.session_grant_cnf_jkt,
        account_id: context.account_id,
        requesting_device_id: context.requesting_device_id,
        trust_domain: context.trust_domain,
        policy_id: context.policy_id,
        policy_version: context.policy_version,
        recovery_session_id: context.recovery_session_id,
        identity_model: context.identity_model,
        model_generation_ref: context.model_generation_ref,
        publication_authority_context_digest: context.publication_authority_context_digest,
        challenge: context.challenge,
        expires_at: context.expires_at,
        created_at: context.created_at,
        proof_body,
    };
    transcript
        .validate()
        .map_err(|error| stored_recovery_type_error("generic recovery transcript", error))?;
    Ok(transcript)
}

/// Lazily expire a session whose TTL has elapsed: if a `pending`/`verified`
/// session is past `expires_at`, persist the `expired` transition and return
/// the updated record. Terminal states are returned unchanged.
pub(super) async fn expire_if_elapsed(
    state: &AppState,
    record: RecoverySessionServiceState,
) -> Result<RecoverySessionServiceState, AppError> {
    let now = chrono::Utc::now();
    let is_open = matches!(record.state, SessionState::Pending | SessionState::Verified);
    if is_open && now > record.expires_at {
        let expired = RecoverySessionServiceState {
            state: SessionState::Expired,
            updated_at: now,
            ..record
        };
        state
            .recovery_sessions()
            .save_session(expired.clone())
            .await
            .map_err(recovery_session_store_error)?;
        return Ok(expired);
    }
    Ok(record)
}
