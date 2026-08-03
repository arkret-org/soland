use ed25519_dalek::Signer as _;
use salvo::oapi::endpoint;

use super::*;

pub(super) fn participation_scope_kind(scope: &ParticipationScope) -> &'static str {
    match scope {
        ParticipationScope::Realm { .. } => "realm",
        ParticipationScope::Circle { .. } => "circle",
        ParticipationScope::Strand { .. } => "strand",
    }
}

pub(super) fn participation_from_value(row: &Value) -> ParticipationBits {
    ParticipationBits {
        reply_message: row
            .get("reply_message")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        reaction_add: row
            .get("reaction_add")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        reaction_remove: row
            .get("reaction_remove")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        accept_third_party_mention: row
            .get("accept_third_party_mention")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        act_on_behalf: row
            .get("act_on_behalf")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    }
}

/// Effective ceiling for a scope = fold(deployment ⊇ Realm ⊇ Circle ⊇
/// Strand). Reads the `agent_participation_ceiling` projection for the
/// enclosing scope_key chain and intersects each row over the deployment
/// default; a scope with no ceiling rows inherits the deployment default
/// (AKP-0010 §4.4, fail-closed by intersection).
pub(super) async fn resolve_effective_ceiling(
    state: &AppState,
    scope: &ParticipationScope,
) -> ParticipationBits {
    crate::routing::agent_participation::resolve_effective_ceiling(state, scope).await
}

pub(super) fn agent_participation_failed_precondition(reason: &'static str) -> AppError {
    AppError::new(ErrorCode::FailedPrecondition, reason)
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_wire_code(reason)
}

#[endpoint(
    operation_id = "ak.self.agent.participation.resource.replace",
    summary = "Replace an agent's participation policy",
    tags("agent_participation")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.participation.resource.replace"))]
pub(super) async fn set_agent_participation(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<ParticipationReplacementBatch>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ParticipationReplaceReceipt> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let agent_id = agent_id.into_inner();
    let record = require_agent_controller(state, &session, &agent_id).await?;
    crate::routing::identity::managed_agent_pcr::validate_agent_controller_binding(
        state,
        &record,
        chrono::Utc::now(),
    )
    .await?;
    let body = body.into_inner();
    body.validate()
        .map_err(|error| AppError::invalid_param(error.to_string()))?;
    if body.agent_id.as_str() != agent_id {
        return Err(AppError::invalid_param(
            "path agent_id does not match participation batch",
        ));
    }
    let (target_service_id, verifier_id, evidence_expires_at) = match &body.scope_evidence {
        ParticipationScopeEvidence::InlineEncrypted { challenge, .. } => (
            &challenge.target_service_id,
            &challenge.verifier_id,
            challenge.expires_at,
        ),
        ParticipationScopeEvidence::AcceptedTargetReceipt {
            target_service_id,
            verifier_id,
            expires_at,
            ..
        } => (target_service_id, verifier_id, *expires_at),
    };
    if target_service_id.as_str() != state.service_id()
        || verifier_id.as_str() != state.service_id()
        || evidence_expires_at <= now()
    {
        return Err(agent_participation_failed_precondition(
            "participation_evidence_conflict",
        ));
    }
    let provision_ceiling = agent_requested_participation_ceiling(&record);
    let ceiling = ParticipationBits {
        reply_message: provision_ceiling.reply_message,
        reaction_add: provision_ceiling.reaction_add,
        reaction_remove: provision_ceiling.reaction_remove,
        accept_third_party_mention: provision_ceiling.accept_third_party_mention,
        act_on_behalf: provision_ceiling.act_on_behalf,
    };
    if !body.selection.is_subset_of(ceiling) {
        return Err(agent_participation_failed_precondition(
            arkret_wire::ReasonCode::AGENT_PARTICIPATION_EXCEEDS_CEILING,
        ));
    }
    for submission in body.grant_events.iter().chain(&body.revoke_events) {
        submission
            .validate_structural()
            .map_err(|error| AppError::invalid_param(error.to_string()))?;
        if submission.event.actor_id.as_str() != session.actor {
            return Err(AppError::capability_denied(
                "participation grant/revoke Events must be controller-authored",
            ));
        }
    }
    let scope_value = serde_json::to_value(&body.target_scope).unwrap_or(Value::Null);
    let scope_key = participation_scope_key(&body.target_scope);
    let current_version = state
        .agent_participations()
        .selections(&agent_id)
        .await
        .map_err(|err| AppError::internal(format!("participation read failed: {err}")))?
        .iter()
        .filter(|row| row.get("scope_key").and_then(Value::as_str) == Some(scope_key.as_str()))
        .filter_map(|row| row.get("version").and_then(Value::as_u64))
        .max()
        .unwrap_or(0);
    if body.expected_version != current_version {
        return Err(agent_participation_failed_precondition(
            "participation_version_conflict",
        ));
    }
    let selection_value = serde_json::to_value(body.selection).unwrap_or(Value::Null);
    let ceiling_value = serde_json::to_value(ceiling).unwrap_or(Value::Null);
    let batch_digest = body
        .base_batch_digest()
        .map_err(|error| AppError::invalid_param(error.to_string()))?;
    let scope_evidence_digest = arkret_identifiers::Hash::new(
        arkret_canonical::canonical_sha256(&body.scope_evidence)
            .map_err(|error| AppError::internal(format!("scope evidence digest: {error}")))?,
    )
    .map_err(|error| AppError::internal(format!("scope evidence digest invalid: {error}")))?;
    let accepted_version = current_version + 1;
    let participation_events = body
        .grant_events
        .iter()
        .chain(&body.revoke_events)
        .cloned()
        .collect::<Vec<_>>();
    if !participation_events.is_empty() {
        let expected = participation_events.len();
        let outcome = crate::routing::events::event_log::submit_initial_event_batch_outcome(
            state,
            &session,
            participation_events,
        )
        .await
        .map_err(|error| {
            AppError::conflict(format!("participation Event batch rejected: {error:?}"))
        })?;
        if outcome.accepted.len() != expected || !outcome.rejected.is_empty() {
            return Err(agent_participation_failed_precondition(
                "participation_event_batch_conflict",
            ));
        }
    }
    state
        .agent_participations()
        .store_selection(json!({
            "agent_id": agent_id,
            "scope_kind": participation_scope_kind_v1(&body.target_scope),
            "scope_key": scope_key,
            "realm_id": body.target_scope.realm_id().as_str(),
            "scope": scope_value.clone(),
            "version": accepted_version,
            "reply_message": body.selection.reply_message,
            "reaction_add": body.selection.reaction_add,
            "reaction_remove": body.selection.reaction_remove,
            "accept_third_party_mention": body.selection.accept_third_party_mention,
            "act_on_behalf": body.selection.act_on_behalf,
            "basis": body.basis,
            "batch_digest": batch_digest,
            "scope_evidence_digest": scope_evidence_digest,
        }))
        .await
        .map_err(|err| AppError::internal(format!("participation persist failed: {err}")))?;
    append_audit_log(
        state,
        Some(&session.actor),
        "ak.self.agent.participation.resource.replace",
        json!({
            "agent_id": agent_id,
            "controller_id": session.actor.clone(),
            "scope": scope_value,
            "scope_key": scope_key,
            "selection": selection_value,
            "ceiling": ceiling_value,
            "batch_digest": batch_digest,
            "accepted_version": accepted_version,
        }),
        "accepted",
    )
    .await;
    // Capability materialization is controller-authored durable history.
    // Inkson submits the matching signed `ak.capability.{grant,revoke}` Event
    // after this aggregate has resolved and persisted the effective selection.
    // Soland must never impersonate the controller, including in development.
    let deployment_ceiling_digest = arkret_identifiers::Hash::new(
        arkret_canonical::canonical_sha256(&ceiling)
            .map_err(|error| AppError::internal(format!("deployment ceiling digest: {error}")))?,
    )
    .map_err(|error| AppError::internal(format!("deployment ceiling digest invalid: {error}")))?;
    let accepted_at = now();
    let target_service_id = Did::new(state.service_id().clone())
        .map_err(|error| AppError::internal(format!("service DID invalid: {error}")))?;
    let verification_method = arkret_wire::DidUrl::new(
        crate::routing::federation::federation_service_signature_key_id(state.service_id()),
    )
    .map_err(|error| AppError::internal(format!("service verification method invalid: {error}")))?;
    let receipt_bytes = arkret_canonical::canonical_json_bytes(&json!({
        "batch_digest": batch_digest,
        "scope_evidence_digest": scope_evidence_digest,
        "deployment_ceiling_digest": deployment_ceiling_digest,
        "deployment_ceiling_version": 1,
        "accepted_version": accepted_version,
        "target_service_id": target_service_id,
        "accepted_at": arkret_canonical::format_timestamp_canonical(accepted_at),
    }))
    .map_err(|error| AppError::internal(format!("participation receipt canonicalize: {error}")))?;
    let signature = state.notary_signing_key().sign(&receipt_bytes);
    json_ok(ParticipationReplaceReceipt {
        batch_digest,
        scope_evidence_digest,
        deployment_ceiling_digest,
        deployment_ceiling_version: 1,
        accepted_version,
        target_service_id,
        accepted_at,
        signature: ProtocolSignature {
            verification_method,
            created_at: accepted_at,
            jws: arkret_wire::Base64UrlString::new(URL_SAFE_NO_PAD.encode(signature.to_bytes()))
                .map_err(|error| {
                    AppError::internal(format!("receipt signature invalid: {error}"))
                })?,
        },
    })
}

fn participation_scope_kind_v1(scope: &ParticipationScope) -> &'static str {
    match scope {
        ParticipationScope::Realm { .. } => "realm",
        ParticipationScope::Circle { .. } => "circle",
        ParticipationScope::Strand { .. } => "strand",
    }
}

fn participation_scope_key(scope: &ParticipationScope) -> String {
    match scope {
        ParticipationScope::Realm { realm_id } => realm_id.to_string(),
        ParticipationScope::Circle {
            realm_id,
            circle_id,
        } => {
            format!("{}|{}", realm_id, circle_id)
        }
        ParticipationScope::Strand {
            realm_id,
            strand_id,
        } => {
            format!("{}|{}", realm_id, strand_id)
        }
    }
}

pub(super) fn normalize_sidecar_exposure_ack(
    value: Option<Value>,
    controller_id: &str,
) -> Result<Option<Value>, AppError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let ack: AgentSidecarExposureAck = serde_json::from_value(value)
        .map_err(|err| AppError::invalid_param(format!("sidecar_exposure_ack invalid: {err}")))?;
    if ack.acknowledged_by.as_str() != controller_id {
        return Err(AppError::capability_denied(
            "sidecar_exposure_ack.acknowledged_by must match the controller session",
        ));
    }
    if ack.sidecar_refs.is_empty() {
        return Err(AppError::invalid_param(
            "sidecar_exposure_ack.sidecar_refs must be non-empty when present",
        ));
    }
    if ack.sidecar_refs.len() > 128 {
        return Err(AppError::invalid_param(
            "sidecar_exposure_ack.sidecar_refs exceeds the 128 item limit",
        ));
    }
    let mut refs = std::collections::BTreeSet::new();
    for sidecar_ref in &ack.sidecar_refs {
        if sidecar_ref.trim().is_empty() {
            return Err(AppError::invalid_param(
                "sidecar_exposure_ack.sidecar_refs must not contain empty refs",
            ));
        }
        if !refs.insert(sidecar_ref.as_str()) {
            return Err(AppError::invalid_param(
                "sidecar_exposure_ack.sidecar_refs must be unique",
            ));
        }
    }
    serde_json::to_value(ack)
        .map(Some)
        .map_err(|err| AppError::internal(format!("sidecar_exposure_ack serialize failed: {err}")))
}

#[endpoint(
    operation_id = "ak.self.agent.participation.resource.get",
    summary = "Get an agent's participation policy",
    tags("agent_participation")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.participation.resource.get"))]
pub(super) async fn get_agent_participation(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentParticipationOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let agent_id = agent_id.into_inner();
    let record = require_agent_controller(state, &session, &agent_id).await?;
    crate::routing::identity::managed_agent_pcr::validate_agent_controller_binding(
        state,
        &record,
        chrono::Utc::now(),
    )
    .await?;
    let selections = state
        .agent_participations()
        .selections(&agent_id)
        .await
        .map_err(|err| AppError::internal(format!("participation read failed: {err}")))?;
    let mut entries = Vec::with_capacity(selections.len());
    for row in &selections {
        let Some(scope_value) = row.get("scope") else {
            continue;
        };
        let Ok(scope) = serde_json::from_value::<ParticipationScope>(scope_value.clone())
        else {
            continue;
        };
        let selection = participation_from_value(row);
        let governance_ceiling = resolve_effective_ceiling(state, &scope).await;
        let ceiling = effective_participation(
            governance_ceiling,
            agent_requested_participation_ceiling(&record),
        );
        let effective = effective_participation(ceiling, selection);
        entries.push(AgentParticipationEntry {
            scope,
            selection,
            ceiling,
            effective,
        });
    }
    json_ok(AgentParticipationOutcome {
        ok: true,
        agent_id,
        entries,
    })
}
