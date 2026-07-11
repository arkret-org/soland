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
// and advances `pending -> verified -> completed` (or `rejected` / `expired`).
//
//   POST recovery-sessions                  — create (snapshot policy + challenge)
//   GET  recovery-sessions/{id}             — read status (principal-isolated)
//   POST recovery-sessions/{id}/proofs      — verify a proof (pending -> verified)
//   POST recovery-sessions/{id}/complete    — finalize (only when state == verified)
//
// C-P3 — `/proofs` verifies the `principal_signing` kind cryptographically
// (Ed25519 over the canonical recovery-proof transcript binding every
// session-defining field) and advances `pending -> verified` ONLY on success.
// Other policy-permitted proof kinds return 501 `recovery_proof_kind_unimplemented`
// rather than silently leaving the session pending.
//
// C-P4 — `/complete` requires the client-signed `ak.device.authorize` material
// (recovery-session.schema.json complete_request), validates every session
// binding (device_id / principal_id / recovery_session_id / ssk_generation +
// cross_signing_binding + device_signature shape), then EMITS the authorize plus
// a `ak.device.list_update` onto the principal's control realm (a deterministic
// per-principal `ak:realm:` auto-materialized by the projector) via
// `accept_local_operations` — real schema validation + reducer apply. The
// session transitions to `completed` and the response is the schema's
// complete_response (authorization_event_id / device_list_update_event_id).
// Remaining nuance (not faked): the SSK signature inside cross_signing_binding
// is not re-verified here (no accepted ak.cross_signing.publish state yet —
// Phase 4), and these ids identify accepted operations in the reducer/projection;
// wiring them into the durable event-envelope read store is Phase 3.

pub(super) fn recovery_session_summary(record: &RecoverySessionRecord) -> Value {
    let mut out = json!({
        "schema": "ak.schema.recovery_session.v1",
        "recovery_session_id": record.recovery_session_id,
        "principal_id": record.principal_id,
        "requesting_device_id": record.requesting_device_id,
        "trust_domain": record.trust_domain,
        "policy_id": record.policy_id,
        "policy_version": record.policy_version,
        "ssk_generation": record.ssk_generation,
        "challenge": record.challenge,
        "state": record.state,
        "created_at": record.created_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "updated_at": record.updated_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "expires_at": record.expires_at.to_rfc3339_opts(SecondsFormat::Millis, true),
    });
    // recovery-session.schema.json: verified/completed sessions MUST carry a
    // proof_summary; rejected sessions MUST carry a rejection_reason_code.
    if matches!(record.state.as_str(), "verified" | "completed")
        && let Some(summary) = recovery_proof_summary(record)
    {
        out["proof_summary"] = summary;
    }
    out
}

/// Derive the `proof_summary{kind, proof_digest, verification_method}` from a
/// session that has a recorded proof. `proof_digest` is the SHA-256 of the
/// canonical recovery-proof transcript, deterministically recomputed from the
/// stored session fields (no separate column needed).
pub(super) fn recovery_proof_summary(record: &RecoverySessionRecord) -> Option<Value> {
    let proof = record.proof_payload.as_ref()?.get("proof")?.as_object()?;
    let kind = proof.get("kind").and_then(Value::as_str)?;
    let verification_method = proof.get("verification_method").and_then(Value::as_str);
    let transcript = recovery_proof_summary_transcript(record, proof)?;
    let transcript_bytes = arkret_sdk::canonical::canonical_json_bytes(&transcript).ok()?;
    let proof_digest = arkret_sdk::canonical::sha256_digest(&transcript_bytes);
    let mut summary = json!({ "kind": kind, "proof_digest": proof_digest });
    if let Some(vm) = verification_method {
        summary["verification_method"] = json!(vm);
    }
    Some(summary)
}

fn recovery_proof_summary_transcript(
    record: &RecoverySessionRecord,
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
    record: &RecoverySessionRecord,
) -> Result<RecoverySessionState, AppError> {
    serde_json::from_value(recovery_session_summary(record))
        .map_err(|error| stored_recovery_type_error("session state", error))
}

pub(super) fn typed_recovery_proof_summary(
    record: &RecoverySessionRecord,
) -> Result<Option<ProofSummary>, AppError> {
    recovery_proof_summary(record)
        .map(|value| {
            serde_json::from_value(value)
                .map_err(|error| stored_recovery_type_error("proof summary", error))
        })
        .transpose()
}

pub(super) fn recovery_session_state_from_record(
    record: &RecoverySessionRecord,
) -> Result<SessionState, AppError> {
    serde_json::from_value(Value::String(record.state.clone()))
        .map_err(|error| stored_recovery_type_error("session state enum", error))
}

/// Load a session and enforce principal isolation: only the authenticated
/// principal (== `session.actor`) may read or act on its own recovery sessions.
pub(super) async fn load_owned_recovery_session(
    aa: &AuthArgs,
    state: &AppState,
    req: &mut Request,
    recovery_session_id: &str,
) -> Result<RecoverySessionRecord, AppError> {
    let session = aa.authenticated_session(state, req).await?;
    let principal = session.actor;
    let record = state
        .persistence
        .recovery_sessions()
        .get(recovery_session_id)
        .await
        .map_err(recovery_store_error)?
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

#[endpoint(
    operation_id = "ak.root.identity.recovery_session.command.create",
    tags("identity", "recovery"),
    summary = "Open a recovery session bound to the active policy (REC-1)",
    status_codes(200, 201, 400, 401, 403, 409, 500)
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
    // Accepted cross-signing generation the requester believes is current. The
    // server snapshots it onto the session; completion (C-P4) MUST reject if the
    // accepted generation has since moved on (device_recovery_ssk_generation_mismatch).
    let ssk_generation = u32::try_from(payload.ssk_generation)
        .ok()
        .filter(|generation| *generation >= 1)
        .ok_or_else(|| AppError::invalid_param("ssk_generation must be >= 1 and fit u32"))?;

    // A session can only be opened against an accepted recovery policy — and the
    // requested trust_domain MUST match it (no domain confusion).
    let active = state
        .persistence
        .recovery_policies()
        .get_active_for_principal(&principal)
        .await
        .map_err(recovery_store_error)?
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

    let now = chrono::Utc::now();
    let record = RecoverySessionRecord {
        recovery_session_id: crate::ids::generate("recovery_session"),
        principal_id: principal.clone(),
        requesting_device_id,
        trust_domain,
        policy_id: active.policy_id.clone(),
        policy_version: active.version,
        ssk_generation,
        policy_payload: active.raw_payload.clone(),
        challenge: generate_recovery_challenge(),
        state: "pending".to_owned(),
        proof_payload: None,
        created_at: now,
        updated_at: now,
        expires_at: now + chrono::Duration::seconds(RECOVERY_SESSION_TTL_SECS),
    };
    state
        .persistence
        .recovery_sessions()
        .insert(record.clone())
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

#[endpoint(
    operation_id = "ak.root.identity.recovery_session.resource.get",
    tags("identity", "recovery"),
    summary = "Read a recovery session status (REC-1)",
    status_codes(200, 401, 403, 404, 500)
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

#[endpoint(
    operation_id = "ak.root.identity.recovery_session.command.submit_proof",
    tags("identity", "recovery"),
    summary = "Submit a recovery proof for a pending session (REC-1)",
    status_codes(200, 400, 401, 403, 404, 409, 500)
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
    let proof = payload
        .proof
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
    let updated = RecoverySessionRecord {
        state: "verified".to_owned(),
        proof_payload: Some(payload_value.clone()),
        updated_at: now,
        ..record
    };
    state
        .persistence
        .recovery_sessions()
        .update(updated.clone())
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
    record: &RecoverySessionRecord,
    proof: &Map<String, Value>,
) -> Result<(), AppError> {
    // recovery-session.schema.json $defs/principal_signing_proof requires `alg`.
    let alg = proof
        .get("alg")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::invalid_param("proof.alg is required"))?;
    if !matches!(alg, "EdDSA" | "Ed25519") {
        return Err(AppError::invalid_param(format!(
            "proof.alg `{alg}` not in {{EdDSA, Ed25519}}",
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
        arkret_sdk::canonical::canonical_json_bytes(&transcript).map_err(|error| {
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
    record: &RecoverySessionRecord,
    proof: &Map<String, Value>,
) -> Result<(), AppError> {
    let alg = required_proof_string(proof, "alg")?;
    if !matches!(alg, "EdDSA" | "Ed25519") {
        return Err(AppError::invalid_param(format!(
            "proof.alg `{alg}` not in {{EdDSA, Ed25519}}",
        )));
    }
    let service_id = required_proof_string(proof, "service_id")?;
    let audience = required_proof_string(proof, "audience")?;
    if audience != state.config.service_id {
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
        arkret_sdk::canonical::canonical_json_bytes(&transcript).map_err(|error| {
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
/// (b) `signature` (under the entry's `alg`, Ed25519) MUST verify over the
///     generic recovery transcript whose proof_body is this proof object with
///     `signature` and `unlock_commitment` removed, using the public key
///     decoded from the entry's verification_method;
/// (c) `unlock_commitment` MUST equal
///     SHA-256(utf8("ak.recovery-session-unlock-binding-v1\n")
///       || utf8(recovery_secret_ref) || unlock_binding_input_bytes),
///     where unlock_binding_input_bytes is the same canonical transcript bytes
///     verified in (b).
pub(super) async fn verify_recovery_unlock_proof(
    _state: &AppState,
    record: &RecoverySessionRecord,
    proof: &Map<String, Value>,
) -> Result<(), AppError> {
    let alg = required_proof_string(proof, "alg")?;
    if alg != "Ed25519" {
        return Err(AppError::invalid_param(format!(
            "proof.alg `{alg}` must be `Ed25519` for recovery_unlock",
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
    let entry_alg = entry.get("alg").and_then(Value::as_str).unwrap_or_default();
    if entry_alg != alg {
        return Err(recovery_evidence_unbound_error(
            "recovery_unlock proof.alg does not match the recovery key entry alg",
        ));
    }
    let recovery_key = decode_recovery_key_public_key(verification_method)?;

    // (b)/(c) Build the binding transcript (proof_body excluding signature +
    // unlock_commitment) once; both the signature and the commitment cover it.
    let mut proof_body = proof.clone();
    proof_body.remove("signature");
    proof_body.remove("unlock_commitment");
    let transcript =
        generic_recovery_proof_transcript(record, "recovery_unlock", Value::Object(proof_body));
    let transcript_bytes =
        arkret_sdk::canonical::canonical_json_bytes(&transcript).map_err(|error| {
            AppError::internal(format!("recovery_unlock transcript failed: {error}"))
        })?;

    // (c) unlock_commitment integrity.
    let mut hasher = Sha256::new();
    hasher.update(b"ak.recovery-session-unlock-binding-v1\n");
    hasher.update(recovery_secret_ref.as_bytes());
    hasher.update(&transcript_bytes);
    let expected_commitment = format!("sha256:{}", hex::encode(hasher.finalize()));
    if !constant_time_str_eq(&unlock_commitment, &expected_commitment) {
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
fn resolve_recovery_key_entry(
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

/// Decode the Ed25519 public key carried self-describingly by a recovery key
/// `verification_method`. The trust root is the principal-signed recovery
/// policy, so the key material is the `did:key` multibase encoded in the
/// verification_method itself (no DID-document lookup): the `z…` multibase is
/// taken from the fragment when present, else from the method-specific id.
fn decode_recovery_key_public_key(verification_method: &str) -> Result<VerifyingKey, AppError> {
    let multibase = recovery_key_multibase(verification_method).ok_or_else(|| {
        recovery_evidence_unbound_error(
            "recovery key verification_method does not carry a did:key multibase public key",
        )
    })?;
    crate::routing::identity::cross_signing::decode_ed25519_key(multibase, "multibase")
        .map_err(|error| recovery_evidence_unbound_error(format!("recovery key invalid: {error}")))
}

/// Extract the base58btc multibase (`z…`) public key from a `did:key`
/// verification method. Accepts `did:key:z…#z…` (fragment carries the key id)
/// and bare `did:key:z…`.
fn recovery_key_multibase(verification_method: &str) -> Option<&str> {
    let body = verification_method.strip_prefix("did:key:")?;
    let candidate = match body.split_once('#') {
        Some((_, fragment)) if fragment.starts_with('z') => fragment,
        Some((id, _)) => id,
        None => body,
    };
    candidate.starts_with('z').then_some(candidate)
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
        "alg": required_proof_string(proof, "alg")?,
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
pub(super) fn recovery_proof_transcript(record: &RecoverySessionRecord, kind: &str) -> Value {
    json!({
        "type": "ak.identity.recovery_proof.v1",
        "kind": kind,
        "principal_id": record.principal_id,
        "requesting_device_id": record.requesting_device_id,
        "trust_domain": record.trust_domain,
        "policy_id": record.policy_id,
        "policy_version": record.policy_version,
        "recovery_session_id": record.recovery_session_id,
        "ssk_generation": record.ssk_generation,
        "challenge": record.challenge,
        // created_at is the SESSION creation/signing time (not proof time), per
        // recovery-session.schema.json $defs/principal_signing_transcript.
        "created_at": record.created_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "expires_at": record.expires_at.to_rfc3339_opts(SecondsFormat::Millis, true),
    })
}

pub(super) fn generic_recovery_proof_transcript(
    record: &RecoverySessionRecord,
    kind: &str,
    proof_body: Value,
) -> Value {
    json!({
        "type": "ak.identity.recovery_proof.v1",
        "kind": kind,
        "principal_id": record.principal_id,
        "requesting_device_id": record.requesting_device_id,
        "trust_domain": record.trust_domain,
        "policy_id": record.policy_id,
        "policy_version": record.policy_version,
        "recovery_session_id": record.recovery_session_id,
        "ssk_generation": record.ssk_generation,
        "challenge": record.challenge,
        "created_at": record.created_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "expires_at": record.expires_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "proof_body": proof_body,
    })
}

#[endpoint(
    operation_id = "ak.root.identity.recovery_session.command.complete",
    tags("identity", "recovery"),
    summary = "Finalize a verified recovery session (REC-1)",
    status_codes(200, 400, 401, 403, 404, 409, 500)
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.root.identity.recovery_session.command.complete")
)]
pub(super) async fn recovery_session_complete(
    aa: AuthArgs,
    recovery_session_id: PathParam<String>,
    body: JsonBody<RecoverySessionCompleteRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RecoverySessionCompleteOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session_id = recovery_session_id.into_inner();
    let complete_request = body.into_inner();
    let authorization_event_id_typed = complete_request.authorization_event_id.clone();
    let device_list_update_event_id_typed = complete_request.device_list_update_event_id.clone();
    let record = load_owned_recovery_session(&aa, state, req, &session_id).await?;
    let record = expire_if_elapsed(state, record).await?;

    // The only path to completion is a `verified` session. Proof verification
    // (C-P3) is what flips `pending -> verified`; until it lands no session can
    // reach `verified`, so this endpoint always rejects rather than fabricating
    // a successful recovery.
    if record.state != "verified" {
        // Registry-canonical `failed_precondition`: completion preconditions
        // (a `verified` session) are not met yet.
        return Err(AppError::conflict(format!(
            "recovery session is `{}`, completion requires `verified`",
            record.state
        ))
        .with_wire_code("failed_precondition"));
    }

    // C-P4 / Phase 3 (durable model) — the recovering client has already
    // submitted, via POST /events on the principal control stream, both a
    // `ak.device.authorize` (SSK-signed; its cross_signing_binding was verified
    // at ingest, §3a) and a `ak.device.list_update`, each a signed Event
    // Envelope carrying the next actor_seq. Completion REFERENCES those durable
    // event ids and verifies they are the right events bound to this session —
    // the server never authors/signs control events on the principal's behalf.
    let authorization_event_id = authorization_event_id_typed.as_str().to_owned();
    let device_list_update_event_id = device_list_update_event_id_typed.as_str().to_owned();

    // Resolve + verify the referenced ak.device.authorize.
    let authorize_payload =
        resolve_control_event_payload(state, &authorization_event_id, "ak.device.authorize")
            .await?;
    if authorize_payload
        .get("principal_id")
        .and_then(Value::as_str)
        != Some(record.principal_id.as_str())
    {
        return Err(AppError::conflict("authorize event principal_id mismatch")
            .with_wire_code("recovery_authorization_principal_mismatch"));
    }
    if authorize_payload.get("device_id").and_then(Value::as_str)
        != Some(record.requesting_device_id.as_str())
    {
        return Err(AppError::conflict("authorize event device_id mismatch")
            .with_wire_code("recovery_authorization_device_mismatch"));
    }
    if authorize_payload
        .get("recovery_session_id")
        .and_then(Value::as_str)
        != Some(record.recovery_session_id.as_str())
    {
        return Err(
            AppError::conflict("authorize event recovery_session_id mismatch")
                .with_wire_code("recovery_authorization_session_mismatch"),
        );
    }
    // Parse the accepted authorize payload into the typed SDK wire shape so
    // the §5.2 transcript fields (device_public_key / hpke_key / algorithms)
    // are checked access, not stringly lookups. Projection-injected envelope
    // fields are stripped first.
    let typed_authorize: arkret_sdk::DeviceAuthorizePayload = serde_json::from_value(
        crate::routing::identity::cross_signing::device_authorize_wire_payload(&authorize_payload),
    )
    .map_err(|error| {
        AppError::invalid_param(format!(
            "authorize event payload is not the typed device_authorize wire shape: {error}"
        ))
    })?;
    let binding = authorize_payload
        .get("cross_signing_binding")
        .and_then(Value::as_object)
        .ok_or_else(|| AppError::invalid_param("authorize event missing cross_signing_binding"))?;
    // Defense-in-depth: re-verify the binding against the accepted SSK (ingest
    // already verified it via §3a, but completion is the irreversible step).
    crate::routing::identity::cross_signing::verify_device_cross_signing_binding(
        state,
        &record.principal_id,
        &record.requesting_device_id,
        &typed_authorize.device_public_key,
        &typed_authorize.hpke_key,
        &typed_authorize.algorithms,
        binding,
    )?;

    // Resolve + verify the referenced ak.device.list_update.
    let list_update_payload =
        resolve_control_event_payload(state, &device_list_update_event_id, "ak.device.list_update")
            .await?;
    if list_update_payload
        .get("principal_id")
        .and_then(Value::as_str)
        != Some(record.principal_id.as_str())
    {
        return Err(
            AppError::conflict("list_update event principal_id mismatch")
                .with_wire_code("recovery_list_update_principal_mismatch"),
        );
    }
    let list_update_covers_device = list_update_payload
        .get("changed")
        .and_then(Value::as_array)
        .is_some_and(|changed| {
            changed
                .iter()
                .any(|d| d.as_str() == Some(record.requesting_device_id.as_str()))
        });
    if !list_update_covers_device {
        return Err(
            AppError::conflict("list_update event does not cover the recovered device")
                .with_wire_code("recovery_list_update_device_mismatch"),
        );
    }

    let now = chrono::Utc::now();
    let proof_summary = record
        .proof_payload
        .as_ref()
        .and_then(|p| p.get("proof"))
        .and_then(Value::as_object)
        .map(|proof| {
            json!({
                "kind": proof.get("kind").cloned().unwrap_or(Value::Null),
                "verification_method": proof
                    .get("verification_method")
                    .cloned()
                    .unwrap_or(Value::Null),
            })
        })
        .unwrap_or(Value::Null);
    let device = DeviceInventoryRecord {
        actor: record.principal_id.clone(),
        device_id: record.requesting_device_id.clone(),
        display_name: None,
        verification_state: "verified".to_owned(),
        payload: json!({
            "recovery": {
                "recovery_session_id": record.recovery_session_id,
                "policy_id": record.policy_id,
                "policy_version": record.policy_version,
                "trust_domain": record.trust_domain,
                "proof_summary": proof_summary,
                "authorized_at": now.to_rfc3339_opts(SecondsFormat::Millis, true),
            },
            // The accepted device key (from the referenced ak.device.authorize),
            // used to verify a later recovery_receipt is signed by THIS device
            // (recovery-receipt.schema.json auth_data.verification_method, §15 step 7).
            "device_public_key": typed_authorize.device_public_key,
            "authorization_event_id": authorization_event_id,
        }),
        created_at: now,
        updated_at: now,
        revoked_at: None,
    };
    state
        .persistence
        .devices()
        .put(&device)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;

    let completed = RecoverySessionRecord {
        state: "completed".to_owned(),
        updated_at: now,
        ..record
    };
    state
        .persistence
        .recovery_sessions()
        .update(completed.clone())
        .await
        .map_err(recovery_session_store_error)?;

    append_audit_log(
        state,
        Some(&completed.principal_id),
        "ak.root.identity.recovery_session.command.complete",
        json!({
            "recovery_session_id": completed.recovery_session_id,
            "device_id": completed.requesting_device_id,
            "policy_id": completed.policy_id,
            "authorization_event_id": authorization_event_id,
            "device_list_update_event_id": device_list_update_event_id,
        }),
        "completed",
    )
    .await;

    json_ok(RecoverySessionCompleteOutcome {
        ok: true,
        recovery_session_id: RecoverySessionId::new(completed.recovery_session_id.clone())
            .map_err(|error| stored_recovery_type_error("recovery_session_id", error))?,
        state: recovery_session_state_from_record(&completed)?,
        device_id: DeviceId::new(completed.requesting_device_id.clone())
            .map_err(|error| stored_recovery_type_error("requesting_device_id", error))?,
        authorization_event_id: authorization_event_id_typed,
        device_list_update_event_id: device_list_update_event_id_typed,
    })
}

/// Phase 3 — resolve a client-submitted control event from the durable event
/// store and return its operation payload (`envelope.payload`). Rejects when the
/// event is absent or not the expected kind. (Events reach the store via the
/// normal `POST /events` path, where §3a verifies the cross_signing_binding at
/// ingest and actor_seq monotonicity is enforced.)
pub(super) async fn resolve_control_event_payload(
    state: &AppState,
    event_id: &str,
    expected_kind: &str,
) -> Result<Value, AppError> {
    let record = state
        .persistence
        .events()
        .get(event_id)
        .await
        .map_err(recovery_store_error)?
        .ok_or_else(|| {
            AppError::conflict(format!("control event `{event_id}` not found"))
                .with_wire_code("recovery_control_event_not_found")
        })?;
    if record.kind != expected_kind {
        return Err(AppError::conflict(format!(
            "control event `{event_id}` is `{}`, expected `{expected_kind}`",
            record.kind
        ))
        .with_wire_code("recovery_control_event_kind_mismatch"));
    }
    record
        .envelope
        .get("payload")
        .cloned()
        .filter(|p| p.is_object())
        .ok_or_else(|| {
            AppError::internal(format!("control event `{event_id}` has no payload object"))
        })
}

/// Lazily expire a session whose TTL has elapsed: if a `pending`/`verified`
/// session is past `expires_at`, persist the `expired` transition and return
/// the updated record. Terminal states are returned unchanged.
pub(super) async fn expire_if_elapsed(
    state: &AppState,
    record: RecoverySessionRecord,
) -> Result<RecoverySessionRecord, AppError> {
    let now = chrono::Utc::now();
    let is_open = matches!(record.state.as_str(), "pending" | "verified");
    if is_open && now > record.expires_at {
        let expired = RecoverySessionRecord {
            state: "expired".to_owned(),
            updated_at: now,
            ..record
        };
        state
            .persistence
            .recovery_sessions()
            .update(expired.clone())
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
