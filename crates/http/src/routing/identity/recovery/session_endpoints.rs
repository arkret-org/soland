use arkret_wire::SchemaId;
use sha2::{Digest as _, Sha256};
use soland_services::identity::RecoverySessionState as RecoverySessionServiceState;

use super::*;

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
// C-P3 — `/proofs` verifies the `principal_signing` kind cryptographically
// (Ed25519 over the canonical recovery-proof transcript binding every
// session-defining field) and advances `pending -> verified` ONLY on success.
// Other policy-permitted proof kinds return 501 `recovery_proof_kind_unimplemented`
// rather than silently leaving the session pending.
//
// Completion is exclusively owned by the bound RecoveryTransaction. There is
// no second public recovery-session completion command.

pub(super) fn recovery_session_summary(record: &RecoverySessionServiceState) -> Value {
    let mut out = json!({
        "schema": "ak.schema.recovery_session.v1",
        "recovery_session_id": record.recovery_session_id,
        "principal_id": record.principal_id,
        "requesting_device_id": record.requesting_device_id,
        "trust_domain": record.trust_domain,
        "policy_id": record.policy_id,
        "policy_version": record.policy_version,
        "identity_model": record.identity_model,
        "publication_authority_context": record.publication_authority_context,
        "publication_authority_context_digest": record.publication_authority_context_digest,
        "challenge": record.challenge,
        "state": record.state,
        "created_at": arkret_canonical::format_timestamp_canonical(record.created_at),
        "updated_at": arkret_canonical::format_timestamp_canonical(record.updated_at),
        "expires_at": arkret_canonical::format_timestamp_canonical(record.expires_at),
    });
    match record.identity_model {
        RecoveryIdentityModel::CrossSigning => {
            out["ssk_generation"] = record
                .ssk_generation
                .map_or(Value::Null, |value| json!(value));
        }
        RecoveryIdentityModel::EnrollmentAuthority => {
            out["current_device_generation_ref"] = record
                .current_device_generation_ref
                .as_ref()
                .map_or(Value::Null, |value| json!(value));
            out["device_generation_status"] = record
                .device_generation_status
                .as_ref()
                .map_or(Value::Null, |value| json!(value));
            out["registry_head"] = record
                .registry_head
                .as_ref()
                .map_or(Value::Null, |value| json!(value));
            out["accepted_seal_frontier"] = record
                .accepted_seal_frontier
                .as_ref()
                .map_or(Value::Null, |value| json!(value));
        }
    }
    // recovery-session.schema.json: verified/completed sessions MUST carry a
    // proof_summary; rejected sessions MUST carry a rejection_reason_code.
    if matches!(record.state.as_str(), "verified" | "completed")
        && let Some(summary) = recovery_proof_summary(record)
    {
        out["proof_summary"] = summary;
    }
    if let Some(transaction_id) = &record.transaction_id {
        out["transaction_id"] = json!(transaction_id);
    }
    out
}

/// Derive the `proof_summary{kind, proof_digest, verification_method}` from a
/// session that has a recorded proof. `proof_digest` is the SHA-256 of the
/// canonical recovery-proof transcript, deterministically recomputed from the
/// stored session fields (no separate column needed).
pub(super) fn recovery_proof_summary(record: &RecoverySessionServiceState) -> Option<Value> {
    let proof = record.proof_payload.as_ref()?.get("proof")?.as_object()?;
    let kind = proof.get("kind").and_then(Value::as_str)?;
    let verification_method = proof.get("verification_method").and_then(Value::as_str);
    let transcript = recovery_proof_summary_transcript(record, proof)?;
    let transcript_bytes = arkret_canonical::canonical_json_bytes(&transcript).ok()?;
    let proof_digest = arkret_canonical::sha256_digest(&transcript_bytes);
    let mut summary = json!({ "kind": kind, "proof_digest": proof_digest });
    if let Some(vm) = verification_method {
        summary["verification_method"] = json!(vm);
    }
    Some(summary)
}

fn recovery_proof_summary_transcript(
    record: &RecoverySessionServiceState,
    proof: &Map<String, Value>,
) -> Option<Value> {
    let kind = proof.get("kind").and_then(Value::as_str)?;
    match kind {
        "trusted_recovery_service" => {
            let proof_body = trusted_recovery_service_proof_body(proof).ok()?;
            Some(generic_recovery_proof_transcript(
                record,
                "trusted_recovery_service",
                proof_body,
            ))
        }
        "recovery_unlock" => {
            // Same binding transcript the proof verification covered:
            // proof_body is the proof object minus signature + unlock_commitment.
            let mut proof_body = proof.clone();
            proof_body.remove("signature");
            proof_body.remove("unlock_commitment");
            Some(generic_recovery_proof_transcript(
                record,
                "recovery_unlock",
                Value::Object(proof_body),
            ))
        }
        _ => Some(recovery_proof_transcript(record, kind)),
    }
}

pub(super) fn typed_recovery_session_state(
    record: &RecoverySessionServiceState,
) -> Result<RecoverySessionState, AppError> {
    serde_json::from_value(recovery_session_summary(record))
        .map_err(|error| stored_recovery_type_error("session state", error))
}

pub(super) fn typed_recovery_proof_summary(
    record: &RecoverySessionServiceState,
) -> Result<Option<ProofSummary>, AppError> {
    recovery_proof_summary(record)
        .map(|value| {
            serde_json::from_value(value)
                .map_err(|error| stored_recovery_type_error("proof summary", error))
        })
        .transpose()
}

pub(super) fn recovery_session_state_from_record(
    record: &RecoverySessionServiceState,
) -> Result<SessionState, AppError> {
    serde_json::from_value(Value::String(record.state.clone()))
        .map_err(|error| stored_recovery_type_error("session state enum", error))
}

fn recovery_model_generation_ref(record: &RecoverySessionServiceState) -> Value {
    match record.identity_model {
        RecoveryIdentityModel::CrossSigning => record
            .ssk_generation
            .map_or(Value::Null, |generation| json!(generation)),
        RecoveryIdentityModel::EnrollmentAuthority => record
            .current_device_generation_ref
            .as_ref()
            .map_or(Value::Null, |generation| json!(generation)),
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
        .with_wire_code("recovery_publication_authority_invalid")),
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
                .with_wire_code("recovery_publication_authority_invalid")
        })?;
    let expected_methods = quorum
        .members
        .iter()
        .map(|device_id| format!("{}#{}", active.principal_id, device_id))
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
        .with_wire_code("recovery_publication_authority_invalid"));
    }

    let leaves = recovery_policy_basis_leaves(&active.acceptance_basis)?;
    let covered = state
        .projections()
        .seal_leaf_union_proof(&leaves)
        .map_err(|error| {
            AppError::conflict(format!(
                "recovery policy acceptance basis cannot be resolved: {error}"
            ))
            .with_wire_code("recovery_publication_authority_invalid")
        })?
        .into_iter()
        .flat_map(|proof| proof.covered_event_digests)
        .map(|digest| digest.to_string())
        .collect::<BTreeSet<_>>();
    let events = state
        .event_queries()
        .accepted_events_for_actor(&active.principal_id)
        .await
        .map_err(recovery_service_error)?;
    for member in &quorum.members {
        let member = member.as_str();
        let latest_authorize = events
            .iter()
            .filter(|event| {
                covered.contains(&event.canonical_digest)
                    && event.kind == arkret_wire::EventKind::DEVICE_AUTHORIZE
                    && event.envelope["payload"]["device_id"].as_str() == Some(member)
            })
            .map(|event| event.actor_seq)
            .max();
        let latest_revoke = events
            .iter()
            .filter(|event| {
                covered.contains(&event.canonical_digest)
                    && event.kind == arkret_wire::EventKind::DEVICE_REVOKE
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
            .with_wire_code("recovery_publication_authority_invalid"));
        }
    }
    Ok(())
}

async fn enrollment_recovery_publication_authority_context(
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
        .with_wire_code("recovery_publication_authority_invalid")
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
        identity_model: RecoveryIdentityModel::EnrollmentAuthority,
        basis_ref: active.acceptance_basis.clone(),
        scope_ref: authority_set_policy.scope_ref.clone(),
        authority_set_ref,
        authority_set_policy,
        allowed_actions: vec![RecoveryPublicationAction::DeviceReanchor],
    };
    context
        .validate_for(RecoveryIdentityModel::EnrollmentAuthority)
        .map_err(|error| {
            AppError::conflict(format!(
                "recovery publication authority context is invalid: {error}"
            ))
            .with_wire_code("recovery_publication_authority_invalid")
        })?;
    Ok(context)
}

async fn cross_signing_recovery_publication_authority_context(
    state: &AppState,
    principal_id: &str,
    realm_id: &RealmId,
    generation: u64,
) -> Result<RecoveryPublicationAuthorityContext, AppError> {
    let events = state
        .event_queries()
        .accepted_events_for_actor(principal_id)
        .await
        .map_err(recovery_service_error)?;
    let source = events
        .iter()
        .filter(|event| {
            event.kind == arkret_wire::EventKind::CROSS_SIGNING_PUBLISH
                && event.envelope["payload"]["generation"].as_u64() == Some(generation)
        })
        .max_by_key(|event| event.actor_seq)
        .ok_or_else(|| {
            AppError::conflict(
                "accepted cross-signing generation has no canonical publish Event source",
            )
            .with_wire_code("cross_signing_state_missing")
        })?;
    let source_digest = Hash::new(source.canonical_digest.clone())
        .map_err(|error| AppError::internal(format!("cross-signing Event digest: {error}")))?;
    let basis_ref = recovery_policy_acceptance_basis(state, realm_id, &source_digest)?;
    let issuer = source.envelope["payload"]["self_signing_key"]["kid"]
        .as_str()
        .ok_or_else(|| {
            AppError::conflict("accepted cross-signing publish has no self-signing method")
                .with_wire_code("cross_signing_state_missing")
        })?;
    let scope_ref = arkret_wire::ScopeRef::Realm {
        realm_id: realm_id.clone(),
    };
    let authority_set_policy = AuthoritySetPolicy {
        schema: SchemaId::AUTHORITY_SET_POLICY_V1.to_owned(),
        authority_set_id: RECOVERY_CROSS_SIGNING_AUTHORITY_SET_ID.to_owned(),
        policy_kind: AuthoritySetPolicyKind::PrincipalControl,
        scope_ref: scope_ref.clone(),
        source: AuthoritySetPolicySource {
            source_kind: AuthoritySetSourceKind::CrossSigningPublish,
            source_ref: source.event_id.clone(),
            source_digest,
            generation_ref: generation.to_string(),
        },
        authorization_rules: vec![AuthoritySetAuthorizationRule {
            rule_id: "cross_signing".to_owned(),
            issuer_role: AuthoritySetIssuerRole::CrossSigningSelfSigning,
            allowed_actions: vec![
                arkret_wire::EventKind::DEVICE_AUTHORIZE.to_owned(),
                arkret_wire::EventKind::DEVICE_LIST_UPDATE.to_owned(),
            ],
            issuers: vec![AuthoritySetIssuer {
                verification_method: DidUrl::new(issuer.to_owned()).map_err(|error| {
                    AppError::conflict(format!(
                        "accepted cross-signing self-signing method is invalid: {error}"
                    ))
                    .with_wire_code("cross_signing_state_missing")
                })?,
            }],
            threshold: 1,
        }],
    };
    let authority_set_ref = AuthoritySetRef {
        authority_set_id: RECOVERY_CROSS_SIGNING_AUTHORITY_SET_ID.to_owned(),
        authority_set_digest: authority_set_policy.digest().map_err(|error| {
            AppError::internal(format!(
                "cross-signing authority policy digest failed: {error}"
            ))
        })?,
    };
    let context = RecoveryPublicationAuthorityContext {
        identity_model: RecoveryIdentityModel::CrossSigning,
        basis_ref,
        scope_ref,
        authority_set_ref,
        authority_set_policy,
        allowed_actions: vec![
            RecoveryPublicationAction::DeviceAuthorize,
            RecoveryPublicationAction::DeviceListUpdate,
        ],
    };
    context
        .validate_for(RecoveryIdentityModel::CrossSigning)
        .map_err(|error| {
            AppError::conflict(format!(
                "cross-signing publication authority context is invalid: {error}"
            ))
            .with_wire_code("recovery_publication_authority_invalid")
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
    if record.principal_id != principal {
        return Err(AppError::new(
            ErrorCode::CapabilityDenied,
            "recovery session belongs to a different principal",
        )
        .with_status(StatusCode::FORBIDDEN)
        .with_wire_code("recovery_principal_isolation"));
    }
    Ok(record)
}

#[salvo::oapi::endpoint(
    operation_id = "ak.root.identity.recovery_session.command.create",
    tags("identity")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.root.identity.recovery_session.command.create")
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
    let principal = session.actor.clone();
    let payload = body.into_inner();

    // `principal_id` is part of the wire contract (recovery-session.schema.json
    // create_request) and MUST equal the authenticated principal — a caller may
    // only open a recovery session for itself.
    if payload.principal_id.as_str() != principal {
        return Err(AppError::new(
            ErrorCode::CapabilityDenied,
            "principal_id does not match the authenticated principal",
        )
        .with_status(StatusCode::FORBIDDEN)
        .with_wire_code("recovery_principal_isolation"));
    }
    let requesting_device_id = payload.requesting_device_id.as_str().to_owned();
    if !requesting_device_id.starts_with("ak:device:") {
        return Err(AppError::invalid_param(format!(
            "requesting_device_id `{requesting_device_id}` must start with ak:device:",
        )));
    }
    let trust_domain = payload.trust_domain.as_str().to_owned();
    if !trust_domain.starts_with("ak:trust_domain:") {
        return Err(AppError::invalid_param(format!(
            "trust_domain `{trust_domain}` must start with ak:trust_domain:",
        )));
    }
    // A session can only be opened against an accepted recovery policy — and the
    // requested trust_domain MUST match it (no domain confusion).
    let active = state
        .recovery_policies()
        .active_policy(&principal)
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
        // recovery session — there is no proof the requester could ever satisfy.
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
    let realm_id = RealmId::new(principal_control_realm_for_did(&principal))
        .map_err(|error| AppError::internal(format!("principal-control Realm id: {error}")))?;
    let (
        identity_model,
        ssk_generation,
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
                AppError::conflict("B-model recovery requires an accepted DID registry head")
                    .with_wire_code("device_reanchor_entry_not_head")
            })?;
        let leaves =
            crate::routing::identity::device_generation::accepted_device_generation_seal_leaves(
                state, &principal, &realm_id,
            )
            .await
            .map_err(recovery_store_error)?;
        let accepted_seal_frontier = if leaves.is_empty() {
            None
        } else {
            // Both roots ship with the frontier. Unlike a Control Move's
            // seal_basis they are not a redundant copy the receiver could
            // recompute: they are the compare-and-swap operands the re-anchor
            // is admitted against (event-auth-state-resolution.md 5.1).
            let view = state
                .projections()
                .effective_seal_view(&leaves, &realm_id)
                .map_err(|error| {
                    AppError::conflict(format!("accepted Seal frontier is invalid: {error}"))
                        .with_wire_code("device_reanchor_frontier_mismatch")
                })?;
            Some(arkret_wire::DeviceReanchorPreFenceBasis {
                leaves,
                control_event_set_root: view.control_event_set_root,
                state_root: view.state_root,
            })
        };
        (
            RecoveryIdentityModel::EnrollmentAuthority,
            None,
            Some(
                NonEmptyString::new(generation.current_ref).map_err(|error| {
                    AppError::internal(format!("invalid accepted device generation ref: {error}"))
                })?,
            ),
            Some(match generation.status {
                crate::routing::identity::device_generation::DeviceGenerationStatus::Active => {
                    DeviceGenerationStatus::Active
                }
                crate::routing::identity::device_generation::DeviceGenerationStatus::Conflicted => {
                    DeviceGenerationStatus::Conflicted
                }
            }),
            Some(Hash::new(registry_head).map_err(|error| {
                AppError::internal(format!("invalid accepted DID registry head: {error}"))
            })?),
            accepted_seal_frontier,
        )
    } else {
        let generation = crate::routing::identity::cross_signing::current_accepted_ssk_generation(
            state, &principal,
        )
        .ok_or_else(|| {
            AppError::conflict("A-model recovery requires an accepted cross-signing generation")
                .with_wire_code("cross_signing_state_missing")
        })?;
        (
            RecoveryIdentityModel::CrossSigning,
            Some(generation),
            None,
            None,
            None,
            None,
        )
    };

    let publication_authority_context = match identity_model {
        RecoveryIdentityModel::CrossSigning => {
            cross_signing_recovery_publication_authority_context(
                state,
                &principal,
                &realm_id,
                ssk_generation.expect("cross-signing branch fixes ssk_generation"),
            )
            .await?
        }
        RecoveryIdentityModel::EnrollmentAuthority => {
            enrollment_recovery_publication_authority_context(state, &active, &realm_id).await?
        }
    };
    let publication_authority_context_digest =
        publication_authority_context.digest().map_err(|error| {
            AppError::internal(format!(
                "recovery publication authority context digest failed: {error}"
            ))
        })?;

    let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let record = RecoverySessionServiceState {
        recovery_session_id: crate::ids::generate("recovery_session"),
        principal_id: principal.clone(),
        requesting_device_id,
        trust_domain,
        policy_id: active.policy_id.clone(),
        policy_version: active.version,
        identity_model,
        ssk_generation,
        current_device_generation_ref,
        device_generation_status,
        registry_head,
        accepted_seal_frontier,
        policy_payload: active.raw_payload.clone(),
        publication_authority_context,
        publication_authority_context_digest,
        challenge: generate_recovery_challenge(),
        state: "pending".to_owned(),
        proof_payload: None,
        transaction_id: None,
        created_at: now,
        updated_at: now,

        expires_at: now + chrono::Duration::seconds(RECOVERY_SESSION_TTL_SECS),
    };
    state
        .recovery_sessions()
        .create_session(record.clone())
        .await
        .map_err(recovery_session_store_error)?;

    append_audit_log(
        state,
        Some(&session.actor),
        "ak.root.identity.recovery_session.command.create",
        json!({
            "recovery_session_id": record.recovery_session_id.clone(),
            "principal_id": record.principal_id.clone(),
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
    fields(op = "ak.root.identity.recovery_session.resource.get")
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
    fields(op = "ak.root.identity.recovery_session.command.submit_proof")
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
    if record.state != "pending" {
        return Err(AppError::conflict(format!(
            "recovery session is `{}`, proofs accepted only while `pending`",
            record.state
        ))
        .with_wire_code("recovery_session_not_pending"));
    }

    let payload = body.into_inner();
    let payload_value = serde_json::to_value(&payload)
        .map_err(|error| AppError::internal(format!("recovery proof submit serialize: {error}")))?;
    let proof = payload_value
        .get("proof")
        .ok_or_else(|| AppError::invalid_param("proof object is required"))?
        .as_object()
        .ok_or_else(|| AppError::invalid_param("proof object is required"))?;
    let proof_kind = proof
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::invalid_param("proof.kind is required"))?;
    if !ALLOWED_PROOF_KINDS.contains(&proof_kind) {
        return Err(AppError::invalid_param(
            format!("proof.kind `{proof_kind}` not in spec enum",),
        )
        .with_wire_code("recovery_proof_kind_unknown"));
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
        .ok_or_else(|| AppError::invalid_param("proof.challenge is required"))?;
    if !constant_time_str_eq(echoed, &record.challenge) {
        return Err(AppError::new(
            ErrorCode::InvalidSignature,
            "proof.challenge does not match the session challenge",
        )
        .with_status(StatusCode::CONFLICT)
        .with_wire_code("recovery_session_challenge_mismatch"));
    }

    // C-P3 — verify the proof by kind. Only `principal_signing` is implemented;
    // other (policy-permitted) kinds return 501 rather than silently leaving the
    // session pending, so a caller is never misled into thinking the server
    // accepted a proof it cannot actually check.
    match proof_kind {
        "principal_signing" => {
            verify_principal_signing_proof(state, &record, proof).await?;
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
            .with_status(StatusCode::NOT_IMPLEMENTED)
            .with_wire_code("recovery_proof_kind_unimplemented"));
        }
    }

    // Proof verified — advance `pending -> verified` and record the proof. The
    // server only reaches this point after a real cryptographic check.
    let now = chrono::Utc::now();
    let updated = RecoverySessionServiceState {
        state: "verified".to_owned(),
        proof_payload: Some(payload_value.clone()),
        updated_at: now,
        ..record
    };
    state
        .recovery_sessions()
        .save_session(updated.clone())
        .await
        .map_err(recovery_session_store_error)?;

    let proof_summary = recovery_proof_summary(&updated).unwrap_or(Value::Null);
    append_audit_log(
        state,
        Some(&updated.principal_id),
        "ak.root.identity.recovery_session.command.submit_proof",
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
        state: recovery_session_state_from_record(&updated)?,
        verification: "verified".to_owned(),
        proof_summary: typed_recovery_proof_summary(&updated)?,
    })
}

/// C-P3 — verify a `principal_signing` recovery proof.
///
/// The proof MUST carry an Ed25519 signature by the principal's signing key
/// over the canonical recovery-proof transcript, which binds every
/// session-defining field: `(principal_id, requesting_device_id, trust_domain,
/// policy_id, policy_version, recovery_session_id, ssk_generation, challenge,
/// created_at, expires_at)`.
/// Because the transcript is reconstructed server-side from the stored session,
/// any proof signed over a different binding (stale policy, replayed across
/// principal/domain, different session) fails verification — this gives the
/// `recovery_evidence_unbound` guarantee for free.
pub(super) async fn verify_principal_signing_proof(
    state: &AppState,
    record: &RecoverySessionServiceState,
    proof: &Map<String, Value>,
) -> Result<(), AppError> {
    // recovery-session.schema.json $defs/principal_signing_proof requires
    // `signature_algorithm` for this raw signature object.
    let signature_algorithm = proof
        .get("signature_algorithm")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::invalid_param("proof.signature_algorithm is required"))?;
    if signature_algorithm != "Ed25519" {
        return Err(AppError::invalid_param(format!(
            "proof.signature_algorithm `{signature_algorithm}` must be `Ed25519`",
        )));
    }
    let verification_method = proof
        .get("verification_method")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::invalid_param("proof.verification_method is required"))?;
    let principal_did = Did::new(record.principal_id.clone())
        .map_err(|error| recovery_signature_error(format!("principal_id DID invalid: {error}")))?;
    // High-risk path: enforce DID document freshness before recovery
    // signature verification (fail-closed-on-stale).
    let resolved_key = crate::jws_verify::resolve_ed25519_verification_key_for_did_fresh(
        state,
        &principal_did,
        verification_method,
    )
    .await
    .map_err(|error| {
        recovery_signature_error(format!("recovery verification key invalid: {error}"))
    })?;

    let transcript = recovery_proof_transcript(record, "principal_signing");
    let transcript_bytes =
        arkret_canonical::canonical_json_bytes(&transcript).map_err(|error| {
            AppError::internal(format!("recovery proof transcript failed: {error}"))
        })?;

    let signature_b64 = proof
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::invalid_param("proof.signature is required"))?;
    let raw = URL_SAFE_NO_PAD
        .decode(signature_b64.as_bytes())
        .or_else(|_| STANDARD.decode(signature_b64.as_bytes()))
        .map_err(|_| recovery_signature_error("proof.signature is not base64/base64url"))?;
    let signature = Signature::from_slice(&raw)
        .map_err(|_| recovery_signature_error("proof.signature must be 64 Ed25519 bytes"))?;
    resolved_key
        .public_key
        .verify(&transcript_bytes, &signature)
        .map_err(|_| {
            crate::metrics::record_digest_mismatch("recovery_proof_digest");
            recovery_signature_error("recovery proof signature verification failed")
        })
}

pub(super) async fn verify_trusted_recovery_service_proof(
    state: &AppState,
    record: &RecoverySessionServiceState,
    proof: &Map<String, Value>,
) -> Result<(), AppError> {
    let signature_algorithm = required_proof_string(proof, "signature_algorithm")?;
    if signature_algorithm != "Ed25519" {
        return Err(AppError::invalid_param(format!(
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
    let _service_id = Did::new(service_id.to_owned()).map_err(|error| {
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
    let transcript =
        generic_recovery_proof_transcript(record, "trusted_recovery_service", proof_body);
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
        return Err(AppError::invalid_param(format!(
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

    // (b)/(c) Build the binding transcript (proof_body excluding signature +
    // unlock_commitment) once; both the signature and the commitment cover it.
    let mut proof_body = proof.clone();
    proof_body.remove("signature");
    proof_body.remove("unlock_commitment");
    let transcript =
        generic_recovery_proof_transcript(record, "recovery_unlock", Value::Object(proof_body));
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
    crate::routing::identity::cross_signing::decode_ed25519_key(multibase, "multibase")
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
        .ok_or_else(|| AppError::invalid_param(format!("proof.{key} is required")))
}

fn trusted_recovery_service_proof_body(proof: &Map<String, Value>) -> Result<Value, AppError> {
    let mut body = json!({
        "kind": "trusted_recovery_service",
        "challenge": required_proof_string(proof, "challenge")?,
        "service_id": required_proof_string(proof, "service_id")?,
        "audience": required_proof_string(proof, "audience")?,
        "verification_method": required_proof_string(proof, "verification_method")?,
        "signature_algorithm": required_proof_string(proof, "signature_algorithm")?,
    });
    if let Some(attestation_ref) = proof
        .get("attestation_ref")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        body["attestation_ref"] = json!(attestation_ref);
    }
    Ok(body)
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
    AppError::new(ErrorCode::InvalidSignature, message.into())
        .with_status(StatusCode::UNAUTHORIZED)
        .with_wire_code("recovery_proof_authority_invalid")
}

/// Canonical recovery-proof transcript binding every session-defining field.
/// Both the requesting device (when signing) and the server (when verifying)
/// MUST construct this identically.
pub(super) fn recovery_proof_transcript(record: &RecoverySessionServiceState, kind: &str) -> Value {
    json!({
        "schema": "ak.identity.recovery_proof.v1",
        "kind": kind,
        "principal_id": record.principal_id,
        "requesting_device_id": record.requesting_device_id,
        "trust_domain": record.trust_domain,
        "policy_id": record.policy_id,
        "policy_version": record.policy_version,
        "recovery_session_id": record.recovery_session_id,
        "identity_model": record.identity_model,
        "model_generation_ref": recovery_model_generation_ref(record),
        "publication_authority_context_digest": record.publication_authority_context_digest,
        "challenge": record.challenge,
        // created_at is the SESSION creation/signing time (not proof time), per
        // recovery-session.schema.json $defs/principal_signing_transcript.
        "created_at": arkret_canonical::format_timestamp_canonical(record.created_at),
        "expires_at": arkret_canonical::format_timestamp_canonical(record.expires_at),
    })
}

pub(super) fn generic_recovery_proof_transcript(
    record: &RecoverySessionServiceState,
    kind: &str,
    proof_body: Value,
) -> Value {
    json!({
        "schema": "ak.identity.recovery_proof.v1",
        "kind": kind,
        "principal_id": record.principal_id,
        "requesting_device_id": record.requesting_device_id,
        "trust_domain": record.trust_domain,
        "policy_id": record.policy_id,
        "policy_version": record.policy_version,
        "recovery_session_id": record.recovery_session_id,
        "identity_model": record.identity_model,
        "model_generation_ref": recovery_model_generation_ref(record),
        "publication_authority_context_digest": record.publication_authority_context_digest,
        "challenge": record.challenge,
        "created_at": arkret_canonical::format_timestamp_canonical(record.created_at),
        "expires_at": arkret_canonical::format_timestamp_canonical(record.expires_at),
        "proof_body": proof_body,
    })
}

/// Lazily expire a session whose TTL has elapsed: if a `pending`/`verified`
/// session is past `expires_at`, persist the `expired` transition and return
/// the updated record. Terminal states are returned unchanged.
pub(super) async fn expire_if_elapsed(
    state: &AppState,
    record: RecoverySessionServiceState,
) -> Result<RecoverySessionServiceState, AppError> {
    let now = chrono::Utc::now();
    let is_open = matches!(record.state.as_str(), "pending" | "verified");
    if is_open && now > record.expires_at {
        let expired = RecoverySessionServiceState {
            state: "expired".to_owned(),
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

/// Generate a 256-bit anti-replay challenge (base64url, no padding). Pulled
/// from the OS CSPRNG.
pub(super) fn generate_recovery_challenge() -> String {
    use rand::RngExt;
    let mut buf = [0u8; 32];
    rand::rng().fill(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}
