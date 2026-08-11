use arkret_event_draft::EventPayloadExt as _;
use salvo::oapi::endpoint;

use super::*;

const AGENT_PROVISION_ALLOCATION_TTL_HOURS: i64 = 24;
const AGENT_PROVISION_ALLOCATION_DOMAIN: &str = "ak.agent-provision-allocation-v1";
const AGENT_PROVISIONING_ABANDONMENT_TTL_SECONDS: i64 = 300;

fn agent_pairing_is_abandoned(record: &soland_services::identity::AgentPairingState) -> bool {
    record
        .provision_event_refs
        .as_ref()
        .and_then(|refs| refs.get("provisioning_abandonment"))
        .and_then(|state| state.get("terminal_outcome"))
        .is_some_and(|outcome| !outcome.is_null())
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, salvo::oapi::ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct AgentProvisioningAbandonmentChallengeRequestBody {
    request_id: arkret_wire::ProtocolOperationId,
    agent_id: DidCoreId,
    principal_control_realm_id: RealmId,
    allocation_handle: arkret_wire::ProtocolOpaqueId,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, salvo::oapi::ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct AgentProvisioningAbandonmentChallengeOutcome {
    request_id: arkret_wire::ProtocolOperationId,
    challenge_id: arkret_wire::ProtocolOpaqueId,
    challenge: arkret_wire::Base64UrlString,
    purpose: String,
    account_subject: Hash,
    agent_id: DidCoreId,
    agent_slug: String,
    principal_control_realm_id: RealmId,
    allocation_handle: arkret_wire::ProtocolOpaqueId,
    consequence_disclosure: Vec<String>,
    dpop_jkt: String,
    audience: DidFullId,
    origin: String,
    trust_domain: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    issued_at: chrono::DateTime<chrono::Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, salvo::oapi::ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct AgentProvisioningAbandonmentRequestBody {
    request_id: arkret_wire::ProtocolOperationId,
    challenge_id: arkret_wire::ProtocolOpaqueId,
    challenge: arkret_wire::Base64UrlString,
    agent_id: DidCoreId,
    principal_control_realm_id: RealmId,
    allocation_handle: arkret_wire::ProtocolOpaqueId,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, salvo::oapi::ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct AgentProvisioningAbandonmentOutcome {
    request_id: arkret_wire::ProtocolOperationId,
    status: String,
    agent_id: DidCoreId,
    principal_control_realm_id: RealmId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    abandoned_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparedAgentProvision {
    outcome: AgentProvisionOutcome,
    slug: String,
    requested_scope: AgentKeyScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pairing_ttl_ms: Option<u64>,
}

fn agent_provision_phase_key(
    phase: &str,
    operation_id: &arkret_wire::ProtocolOperationId,
    idempotency_key: &arkret_wire::IdempotencyKey,
) -> String {
    format!(
        "agent-provision:{phase}:{}:{}",
        operation_id.as_str(),
        idempotency_key.as_str()
    )
}

fn agent_provision_request_hash(body: &AgentProvisionRequestBody) -> Result<String, AppError> {
    arkret_canonical::canonical_sha256(&serde_json::to_value(body).map_err(|error| {
        AppError::invalid_param(format!("Agent provision request invalid: {error}"))
    })?)
    .map(|digest| digest.to_string())
    .map_err(|error| AppError::internal(format!("Agent provision request digest failed: {error}")))
}

fn allocation_binding(
    controller_id: &str,
    operation_id: &arkret_wire::ProtocolOperationId,
    idempotency_key: &arkret_wire::IdempotencyKey,
    nonce: &str,
) -> Result<Vec<u8>, AppError> {
    arkret_canonical::canonical::canonical_json_bytes(&json!({
        "domain": AGENT_PROVISION_ALLOCATION_DOMAIN,
        "controller_id": controller_id,
        "operation_id": operation_id,
        "idempotency_key": idempotency_key,
        "nonce": nonce,
    }))
    .map_err(|error| AppError::internal(format!("Agent allocation binding failed: {error}")))
}

fn issue_allocation_handle(
    state: &AppState,
    controller_id: &str,
    operation_id: &arkret_wire::ProtocolOperationId,
    idempotency_key: &arkret_wire::IdempotencyKey,
) -> Result<arkret_wire::ProtocolOpaqueId, AppError> {
    use ed25519_dalek::Signer as _;

    let nonce = uuid::Uuid::now_v7().simple().to_string();
    let binding = allocation_binding(controller_id, operation_id, idempotency_key, &nonce)?;
    let signing_key = state.notary_signing_key();
    let signature = signing_key.sign(&binding);
    arkret_wire::ProtocolOpaqueId::new(format!(
        "{nonce}.{}.{}",
        URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
    .map_err(|error| AppError::internal(format!("generated allocation handle invalid: {error}")))
}

fn verify_allocation_handle(
    controller_id: &str,
    operation_id: &arkret_wire::ProtocolOperationId,
    idempotency_key: &arkret_wire::IdempotencyKey,
    handle: &arkret_wire::ProtocolOpaqueId,
) -> Result<(), AppError> {
    let mut parts = handle.as_str().split('.');
    let (Some(nonce), Some(encoded_public_key), Some(encoded_signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "Agent provision allocation handle is malformed",
        )
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_reason_code("agent_provision_allocation_mismatch"));
    };
    let public_key_bytes = URL_SAFE_NO_PAD.decode(encoded_public_key).map_err(|_| {
        AppError::new(
            ErrorCode::FailedPrecondition,
            "Agent provision allocation handle public key is malformed",
        )
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_reason_code("agent_provision_allocation_mismatch")
    })?;
    let public_key_bytes: [u8; 32] = public_key_bytes.try_into().map_err(|_| {
        AppError::new(
            ErrorCode::FailedPrecondition,
            "Agent provision allocation handle public key is malformed",
        )
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_reason_code("agent_provision_allocation_mismatch")
    })?;
    let verifying_key =
        ed25519_dalek::VerifyingKey::from_bytes(&public_key_bytes).map_err(|_| {
            AppError::new(
                ErrorCode::FailedPrecondition,
                "Agent provision allocation handle public key is malformed",
            )
            .with_status(StatusCode::PRECONDITION_FAILED)
            .with_reason_code("agent_provision_allocation_mismatch")
        })?;
    let signature_bytes = URL_SAFE_NO_PAD.decode(encoded_signature).map_err(|_| {
        AppError::new(
            ErrorCode::FailedPrecondition,
            "Agent provision allocation handle signature is malformed",
        )
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_reason_code("agent_provision_allocation_mismatch")
    })?;
    let signature = ed25519_dalek::Signature::from_slice(&signature_bytes).map_err(|_| {
        AppError::new(
            ErrorCode::FailedPrecondition,
            "Agent provision allocation handle signature is malformed",
        )
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_reason_code("agent_provision_allocation_mismatch")
    })?;
    let binding = allocation_binding(controller_id, operation_id, idempotency_key, nonce)?;
    verifying_key.verify(&binding, &signature).map_err(|_| {
        AppError::new(
            ErrorCode::FailedPrecondition,
            "Agent provision allocation handle signature is invalid",
        )
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_reason_code("agent_provision_allocation_mismatch")
    })
}

async fn lookup_provision_allocation(
    state: &AppState,
    controller_id: &str,
    key: &str,
) -> Result<Option<soland_services::jobs::IdempotencyState>, AppError> {
    state
        .jobs()
        .idempotency_record(controller_id, key)
        .await
        .map_err(|error| {
            AppError::internal(format!("Agent provision allocation lookup failed: {error}"))
        })
}

fn allocation_missing() -> AppError {
    AppError::new(
        ErrorCode::FailedPrecondition,
        "Agent provision commit has no active server allocation",
    )
    .with_status(StatusCode::PRECONDITION_FAILED)
    .with_reason_code("agent_provision_allocation_missing")
}

fn allocation_mismatch() -> AppError {
    AppError::new(
        ErrorCode::FailedPrecondition,
        "Agent provision commit differs from its server allocation",
    )
    .with_status(StatusCode::PRECONDITION_FAILED)
    .with_reason_code("agent_provision_allocation_mismatch")
}

#[endpoint(
    operation_id = "ak.self.agent.command.provision",
    summary = "Provision an agent",
    tags("agents")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.command.provision"))]
pub(super) async fn provision_agent(
    aa: AuthArgs,
    body: JsonBody<AgentProvisionRequestBody>,
    depot: &mut Depot,
    res: &mut Response,
    req: &mut Request,
) -> JsonResult<AgentProvisionOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let controller_id = session.actor.clone();
    let body = body.into_inner();
    let request_hash = agent_provision_request_hash(&body)?;
    let now_utc = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
        chrono::Utc::now().timestamp_millis(),
    )
    .ok_or_else(|| AppError::internal("current agent provision timestamp is out of range"))?;

    match body {
        AgentProvisionRequestBody::Prepare {
            operation_id,
            idempotency_key,
            slug,
            requested_scope,
            pairing_ttl_ms,
        } => {
            let key = agent_provision_phase_key("prepare", &operation_id, &idempotency_key);
            if let Some(record) = lookup_provision_allocation(state, &controller_id, &key).await? {
                if record.expires_at <= now_utc {
                    state
                        .jobs()
                        .prune_expired_idempotency(now_utc)
                        .await
                        .map_err(|error| {
                            AppError::internal(format!(
                                "expired allocation cleanup failed: {error}"
                            ))
                        })?;
                } else if record.request_hash != request_hash {
                    return Err(AppError::conflict(
                        "Agent provision prepare idempotency key was reused with different inputs",
                    ));
                } else {
                    let prepared: PreparedAgentProvision =
                        serde_json::from_value(record.response_body).map_err(|error| {
                            AppError::internal(format!(
                                "stored Agent provision allocation invalid: {error}"
                            ))
                        })?;
                    if let AgentProvisionOutcome::AwaitingControllerEvent { agent_id, .. } =
                        &prepared.outcome
                        && state
                            .agent_pairings()
                            .agent(agent_id.as_str())
                            .await
                            .map_err(|error| {
                                AppError::internal(format!(
                                    "Agent provision abandonment lookup failed: {error}"
                                ))
                            })?
                            .as_ref()
                            .is_some_and(agent_pairing_is_abandoned)
                    {
                        // Abandonment suppresses every holder-readable trace of
                        // the old allocation. The durable record remains only
                        // as a no-reuse tombstone.
                        return Err(AppError::not_found("Agent provision allocation not found"));
                    }
                    return json_ok(prepared.outcome);
                }
            }

            let prepared_slug = arkret_wire::string_profiles::prepare_agent_slug(&slug)
                .map_err(|error| AppError::invalid_param(format!("slug is invalid: {error}")))?;
            if prepared_slug != slug {
                return Err(AppError::invalid_param(
                    "slug must already use the canonical agent-slug profile",
                ));
            }
            validate_agent_slug(&slug)
                .map_err(|error| AppError::invalid_param(format!("slug is invalid: {error}")))?;
            let active_recovery_policy = state
                .recovery_policies()
                .active_policy(&controller_id)
                .await
                .map_err(|error| {
                    AppError::internal(format!("controller recovery policy lookup failed: {error}"))
                })?;
            if active_recovery_policy.is_none() {
                return Err(AppError::new(
                    ErrorCode::FailedPrecondition,
                    "controller must accept a recovery policy before provisioning a managed Agent",
                )
                .with_status(StatusCode::PRECONDITION_FAILED)
                .with_reason_code("recovery_policy_required"));
            }
            let controller_realm =
                require_controller_principal_control_realm(state, &session).await?;
            let mut existing = state
                .agent_pairings()
                .agents_for_controller(&controller_id)
                .await
                .map_err(|error| {
                    AppError::internal(format!("agent slug conflict check failed: {error}"))
                })?;
            for record in &mut existing {
                *record = lazily_expire_pairing(state, record.clone()).await?;
            }
            if existing.iter().any(|record| {
                record.agent_slug.as_deref() == Some(slug.as_str())
                    && agent_record_reserves_selector_slug(record, &now_utc)
            }) {
                return Err(AppError::invalid_param(
                    "slug is already bound to an active or open agent for this controller",
                ));
            }

            let agent_full_id = DidFullId::new(generate_agent_principal_did(
                &state.config().public_base_url,
            )?)
            .map_err(|error| AppError::internal(format!("generated Agent DID invalid: {error}")))?;
            let agent_id = arkret_wire::project_full_id_to_core_id(&agent_full_id)
                .map(arkret_wire::DidCoreId::from)
                .map_err(|error| {
                    AppError::internal(format!("generated Agent core id invalid: {error}"))
                })?;
            let controller_did = arkret_identifiers::DidCoreId::new(controller_id.clone())
                .map_err(|error| AppError::internal(format!("controller DID invalid: {error}")))?;
            let requested_scope_digest = arkret_signatures::agent::agent_requested_scope_digest(
                &agent_id,
                &controller_did,
                &requested_scope,
            )
            .map_err(|error| {
                AppError::internal(format!("requested_scope digest failed: {error}"))
            })?;
            let controller_authorization_ref =
                crate::routing::identity::managed_agent_pcr::controller_authorization_ref(
                    &agent_full_id,
                )?;
            let allocation_handle =
                issue_allocation_handle(state, &controller_id, &operation_id, &idempotency_key)?;
            let outcome = AgentProvisionOutcome::AwaitingControllerEvent {
                agent_id,
                full_id: agent_full_id,
                controller_realm_id: RealmId::new(controller_realm).map_err(|error| {
                    AppError::internal(format!("controller PCR id invalid: {error}"))
                })?,
                allocation_handle,
                controller_authorization_ref,
                requested_scope_digest,
            };
            let prepared = PreparedAgentProvision {
                outcome: outcome.clone(),
                slug,
                requested_scope,
                pairing_ttl_ms,
            };
            state
                .jobs()
                .store_idempotency_record(soland_services::jobs::IdempotencyState {
                    principal_id: controller_id.clone(),
                    idempotency_key: key.clone(),
                    service_id: state.service_id().clone(),
                    request_hash: request_hash.clone(),
                    response_status: i32::from(StatusCode::OK.as_u16()),
                    response_body: serde_json::to_value(&prepared).map_err(|error| {
                        AppError::internal(format!(
                            "Agent provision prepare outcome failed: {error}"
                        ))
                    })?,
                    created_at: now_utc,
                    expires_at: now_utc
                        + chrono::Duration::hours(AGENT_PROVISION_ALLOCATION_TTL_HOURS),
                })
                .await
                .map_err(|error| {
                    AppError::internal(format!(
                        "Agent provision allocation persist failed: {error}"
                    ))
                })?;

            let landed = lookup_provision_allocation(state, &controller_id, &key)
                .await?
                .ok_or_else(|| {
                    AppError::internal("Agent provision allocation disappeared after persist")
                })?;
            if landed.request_hash != request_hash {
                return Err(AppError::conflict(
                    "Agent provision prepare lost a concurrent idempotency race",
                ));
            }
            let landed: PreparedAgentProvision = serde_json::from_value(landed.response_body)
                .map_err(|error| {
                    AppError::internal(format!(
                        "stored Agent provision allocation invalid: {error}"
                    ))
                })?;
            json_ok(landed.outcome)
        }
        AgentProvisionRequestBody::Commit {
            operation_id,
            idempotency_key,
            agent_id,
            full_id,
            principal_control_realm_id,
            allocation_handle,
            slug,
            requested_scope,
            provision_event,
            pairing_ttl_ms,
        } => {
            let prepare_key = agent_provision_phase_key("prepare", &operation_id, &idempotency_key);
            let allocation = lookup_provision_allocation(state, &controller_id, &prepare_key)
                .await?
                .filter(|record| {
                    record.expires_at > now_utc && record.service_id == *state.service_id()
                })
                .ok_or_else(allocation_missing)?;
            let prepared: PreparedAgentProvision =
                serde_json::from_value(allocation.response_body.clone()).map_err(|error| {
                    AppError::internal(format!(
                        "stored Agent provision allocation invalid: {error}"
                    ))
                })?;
            let AgentProvisionOutcome::AwaitingControllerEvent {
                agent_id: allocated_agent_id,
                full_id: allocated_full_id,
                controller_realm_id,
                allocation_handle: allocated_handle,
                controller_authorization_ref,
                requested_scope_digest,
            } = prepared.outcome
            else {
                return Err(AppError::internal(
                    "stored Agent provision prepare outcome has a terminal status",
                ));
            };
            if allocation.request_hash
                != agent_provision_request_hash(&AgentProvisionRequestBody::Prepare {
                    operation_id: operation_id.clone(),
                    idempotency_key: idempotency_key.clone(),
                    slug: slug.clone(),
                    requested_scope: requested_scope.clone(),
                    pairing_ttl_ms,
                })?
                || allocated_agent_id != agent_id
                || allocated_full_id != full_id
                || allocated_handle != allocation_handle
                || prepared.slug != slug
                || prepared.requested_scope != requested_scope
                || prepared.pairing_ttl_ms != pairing_ttl_ms
            {
                return Err(allocation_mismatch());
            }
            verify_allocation_handle(
                &controller_id,
                &operation_id,
                &idempotency_key,
                &allocation_handle,
            )?;

            let controller_realm_now =
                require_controller_principal_control_realm(state, &session).await?;
            if controller_realm_id.as_str() != controller_realm_now {
                return Err(allocation_mismatch());
            }
            let provision_payload =
                arkret_models_collaboration::events_payloads::agent::AgentProvisionPayload::try_from(
                    &provision_event.event,
                )
                .map_err(|error| AppError::invalid_param(error.to_string()))?;
            if provision_event.event.actor_id.as_str() != controller_id
                || provision_event.event.realm_id != controller_realm_id
                || provision_payload.agent_id != agent_id
                || provision_payload.controller_id.as_str() != controller_id
                || provision_payload.principal_control_realm_id != principal_control_realm_id
                || provision_payload.controller_authorization_ref != controller_authorization_ref
                || provision_payload.agent_slug != slug
                || provision_payload.requested_scope_digest != requested_scope_digest
            {
                return Err(AppError::invalid_param(
                    "provision_event does not match its authenticated allocation",
                ));
            }

            let requested_scope_value =
                serde_json::to_value(&requested_scope).map_err(|error| {
                    AppError::invalid_param(format!("requested_scope is invalid: {error}"))
                })?;
            let provision_event_id = provision_event.event.event_id.to_string();
            let commit_key = agent_provision_phase_key("commit", &operation_id, &idempotency_key);
            if let Some(record) =
                lookup_provision_allocation(state, &controller_id, &commit_key).await?
            {
                if record.request_hash != request_hash {
                    return Err(AppError::conflict(
                        "Agent provision commit idempotency key was reused with different inputs",
                    ));
                }
                let outcome = serde_json::from_value(record.response_body).map_err(|error| {
                    AppError::internal(format!(
                        "stored Agent provision commit outcome invalid: {error}"
                    ))
                })?;
                res.status_code(StatusCode::CREATED);
                return json_ok(outcome);
            }
            let mut existing = state
                .agent_pairings()
                .agents_for_controller(&controller_id)
                .await
                .map_err(|error| AppError::internal(format!("agent lookup failed: {error}")))?;
            for record in &mut existing {
                *record = lazily_expire_pairing(state, record.clone()).await?;
            }
            let existing_record = existing
                .iter()
                .find(|record| record.id == agent_id.as_str())
                .cloned();
            if let Some(record) = existing_record.as_ref() {
                if agent_pairing_is_abandoned(record) {
                    return Err(AppError::not_found("Agent provision allocation not found"));
                }
                let replay_matches = record.controller_id == controller_id
                    && record.principal_control_realm_id == principal_control_realm_id.as_str()
                    && record.agent_slug.as_deref() == Some(slug.as_str())
                    && record.requested_scope.as_ref() == Some(&requested_scope_value)
                    && record.provision_event_refs.as_ref().is_some_and(|refs| {
                        refs.get("provision_event_id").and_then(Value::as_str)
                            == Some(provision_event_id.as_str())
                            && refs.get("commit_request_hash").and_then(Value::as_str)
                                == Some(request_hash.as_str())
                            && refs.get("operation_id").and_then(Value::as_str)
                                == Some(operation_id.as_str())
                            && refs.get("idempotency_key").and_then(Value::as_str)
                                == Some(idempotency_key.as_str())
                            && refs.get("allocation_handle").and_then(Value::as_str)
                                == Some(allocation_handle.as_str())
                    });
                if !replay_matches {
                    return Err(AppError::conflict(
                        "Agent provision commit reuses an allocation with different inputs",
                    ));
                }
            }
            if existing_record.is_none()
                && existing.iter().any(|record| {
                    record.agent_slug.as_deref() == Some(slug.as_str())
                        && agent_record_reserves_selector_slug(record, &now_utc)
                })
            {
                return Err(AppError::invalid_param(
                    "slug is already bound to an active or open agent for this controller",
                ));
            }

            let mut principal = if let Some(record) = existing_record {
                record
            } else {
                let accepted_provision_event_id = submit_provision_event(
                    state,
                    &session,
                    &controller_realm_now,
                    &agent_id,
                    &principal_control_realm_id,
                    &controller_authorization_ref,
                    &slug,
                    &requested_scope_digest,
                    *provision_event,
                )
                .await?;
                debug_assert_eq!(accepted_provision_event_id, provision_event_id);

                let mut principal = AgentPrincipalRecord::new(
                    agent_id.to_string(),
                    controller_id.clone(),
                    principal_control_realm_id.as_str().to_owned(),
                    controller_authorization_ref.clone(),
                    AgentLifecycleState::Active,
                    allocation.created_at,
                );
                principal.agent_slug = Some(slug.clone());
                principal.requested_scope = Some(requested_scope_value.clone());
                principal.provision_event_refs = Some(json!({
                    "provision_event_id": accepted_provision_event_id,
                    "operation_id": operation_id,
                    "idempotency_key": idempotency_key,
                    "allocation_handle": allocation_handle,
                    "commit_request_hash": request_hash,
                    "pcr_genesis_accepted": false,
                }));
                state
                    .agent_pairings()
                    .save_agent(principal.clone())
                    .await
                    .map_err(|error| {
                        AppError::internal(format!(
                            "Agent provision reservation persist failed: {error}"
                        ))
                    })?;
                principal
            };

            let Some(pcr_genesis_accepted_at) =
                crate::routing::identity::managed_agent_pcr::managed_agent_pcr_genesis_accepted_at(
                    state,
                    agent_id.as_str(),
                    principal_control_realm_id.as_str(),
                )
                .await?
            else {
                return json_ok(AgentProvisionOutcome::AwaitingPcrGenesis {
                    agent_id,
                    full_id,
                    principal_control_realm_id,
                    allocation_handle,
                    controller_authorization_ref,
                    requested_scope_digest,
                });
            };

            crate::routing::identity::managed_agent_pcr::persist_managed_agent_did_identity_anchor(
                state,
                &full_id,
                pcr_genesis_accepted_at,
            )
            .await?;
            let controller_account = state
                .identities()
                .find_account_by_actor(soland_services::identity::FindAccountByActorQuery {
                    actor_id: session.actor.clone(),
                })
                .await
                .map_err(|error| {
                    AppError::internal(format!("controller account lookup failed: {error}"))
                })?
                .ok_or_else(|| AppError::internal("controller account is missing"))?;
            let pairing_request_id = arkret_wire::OpaqueLocalId::new(format!(
                "agent_pairing_request:{}",
                uuid::Uuid::now_v7()
            ))
            .expect("generated pairing request id must be valid");
            let pairing_code = generate_pairing_code();
            let effective_pairing_ttl_ms = pairing_ttl_ms
                .unwrap_or(15 * 60 * 1000)
                .min(12 * 60 * 60 * 1000);
            let expires_at =
                now_utc + chrono::Duration::milliseconds(effective_pairing_ttl_ms as i64);
            principal.controller_account_id = Some(ids::typed_uuid_part_expect_internal(
                &controller_account.account_id,
            ));
            principal.recipient_service_id = Some(state.service_id().clone());
            principal.provision_event_refs = Some(json!({
                "provision_event_id": provision_event_id,
                "operation_id": operation_id,
                "idempotency_key": idempotency_key,
                "allocation_handle": allocation_handle,
                "commit_request_hash": request_hash,
                "pcr_genesis_accepted": true,
            }));
            principal.pairing_request_id = Some(pairing_request_id.clone());
            principal.pairing_code = Some(pairing_code.clone());
            principal.pairing_expires_at = Some(expires_at);
            state
                .agent_pairings()
                .save_agent(principal)
                .await
                .map_err(|error| AppError::internal(format!("agent persist failed: {error}")))?;

            let outcome = AgentProvisionOutcome::Complete {
                outcome: arkret_models_collaboration::agent_operations::AgentProvisionComplete {
                    agent_id: agent_id.clone(),
                    full_id: full_id.clone(),
                    principal_control_realm_id: principal_control_realm_id.clone(),
                    controller_authorization_ref: controller_authorization_ref.clone(),
                    requested_scope_digest: requested_scope_digest.clone(),
                    pcr_recovery: AgentProvisionPcrRecovery::default(),
                    pairing_request_id: pairing_request_id.clone(),
                    pairing_code: Some(pairing_code.clone()),
                    expires_at,
                },
            };
            state
                .jobs()
                .store_idempotency_record(soland_services::jobs::IdempotencyState {
                    principal_id: controller_id.clone(),
                    idempotency_key: commit_key,
                    service_id: state.service_id().clone(),
                    request_hash,
                    response_status: i32::from(StatusCode::CREATED.as_u16()),
                    response_body: serde_json::to_value(&outcome).map_err(|error| {
                        AppError::internal(format!(
                            "Agent provision commit outcome failed: {error}"
                        ))
                    })?,
                    created_at: now_utc,
                    expires_at: allocation.expires_at,
                })
                .await
                .map_err(|error| {
                    AppError::internal(format!("Agent provision commit persist failed: {error}"))
                })?;
            append_audit_log(
                state,
                Some(&session.actor),
                "ak.self.agent.command.provision",
                json!({
                    "agent_id": agent_id,
                    "controller_id": controller_id,
                    "slug": slug,
                    "pairing_request_id": pairing_request_id,
                    "principal_control_realm_id": principal_control_realm_id,
                    "controller_authorization_ref": controller_authorization_ref,
                    "requested_scope_digest": requested_scope_digest,
                    "provision_event_id": provision_event_id,
                }),
                "accepted",
            )
            .await;
            res.status_code(StatusCode::CREATED);
            json_ok(outcome)
        }
    }
}

fn abandonment_request_digest(value: &impl serde::Serialize) -> Result<String, AppError> {
    arkret_canonical::canonical_sha256(value)
        .map_err(|error| AppError::invalid_param(format!("abandonment request invalid: {error}")))
}

fn abandonment_credential_fingerprint(session: &SessionRecord) -> String {
    session.token_hash.clone()
}

fn abandonment_dpop_jkt(session: &SessionRecord) -> Result<String, AppError> {
    session
        .session_grant
        .as_ref()
        .map(|grant| grant.cnf_jkt.clone())
        .filter(|thumbprint| {
            thumbprint.len() == 43
                && thumbprint
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::FailedPrecondition,
                "Agent provisioning abandonment requires a DPoP-bound session grant",
            )
            .with_status(StatusCode::PRECONDITION_FAILED)
        })
}

fn abandonment_storage_error(
    outcome: soland_storage::AgentProvisioningAbandonmentWriteOutcome,
    issuing: bool,
) -> Result<Value, AppError> {
    use soland_storage::AgentProvisioningAbandonmentWriteOutcome as Outcome;
    match outcome {
        Outcome::Challenge(value) | Outcome::Abandoned(value) => Ok(value),
        Outcome::NotFound => Err(AppError::not_found("Agent provisioning not found")),
        Outcome::ProvisionMismatch => Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "Agent provisioning abandonment does not match the durable allocation",
        )
        .with_status(StatusCode::PRECONDITION_FAILED)),
        Outcome::GenesisAccepted => Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "managed Agent PCR genesis is already accepted",
        )
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_reason_code("agent_pcr_genesis_already_accepted")),
        Outcome::ChallengeMissing => Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "Agent provisioning abandonment challenge was not issued",
        )
        .with_status(StatusCode::PRECONDITION_FAILED)),
        Outcome::ChallengeExpired => Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "Agent provisioning abandonment challenge expired",
        )
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_reason_code("agent_provisioning_challenge_expired")),
        Outcome::ChallengeConsumed => {
            let error = if issuing {
                AppError::conflict(
                    "Agent provisioning abandonment request_id was reused with different intent",
                )
            } else {
                AppError::new(
                    ErrorCode::FailedPrecondition,
                    "Agent provisioning abandonment challenge was already consumed",
                )
                .with_status(StatusCode::PRECONDITION_FAILED)
                .with_reason_code("agent_provisioning_challenge_already_consumed")
            };
            Err(error)
        }
        Outcome::CredentialReused => Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "abandonment confirmation must use credentials fresh from challenge issuance",
        )
        .with_status(StatusCode::PRECONDITION_FAILED)),
    }
}

#[endpoint(
    operation_id = "ak.self.agent.command.issue_provisioning_abandonment_challenge",
    summary = "Issue an Agent provisioning abandonment challenge",
    tags("agents")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.self.agent.command.issue_provisioning_abandonment_challenge")
)]
pub(super) async fn issue_provisioning_abandonment_challenge(
    aa: AuthArgs,
    body: JsonBody<AgentProvisioningAbandonmentChallengeRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentProvisioningAbandonmentChallengeOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let record = state
        .agent_pairings()
        .agent(body.agent_id.as_str())
        .await
        .map_err(|error| AppError::internal(format!("Agent provisioning lookup failed: {error}")))?
        .ok_or_else(|| AppError::not_found("Agent provisioning not found"))?;
    if record.controller_id != session.actor {
        return Err(AppError::not_found("Agent provisioning not found"));
    }
    let agent_slug = record
        .agent_slug
        .clone()
        .or_else(|| {
            record
                .provision_event_refs
                .as_ref()
                .and_then(|refs| refs.pointer("/provisioning_abandonment/released_agent_slug"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::FailedPrecondition,
                "Agent provisioning has no durable selector claim",
            )
            .with_status(StatusCode::PRECONDITION_FAILED)
        })?;
    let account_slot = state
        .event_queries()
        .identity_anchor_account_slot_for_principal(&session.actor)
        .await
        .map_err(|error| {
            AppError::internal(format!("controller identity-anchor lookup failed: {error}"))
        })?
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::FailedPrecondition,
                "controller identity-anchor account binding is unavailable",
            )
            .with_status(StatusCode::PRECONDITION_FAILED)
        })?;
    let issued_at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
        chrono::Utc::now().timestamp_millis(),
    )
    .ok_or_else(|| AppError::internal("current abandonment timestamp is out of range"))?;
    let challenge_id = arkret_wire::ProtocolOpaqueId::new(format!(
        "agent-provisioning-abandonment:{}",
        uuid::Uuid::now_v7()
    ))
    .map_err(|error| AppError::internal(format!("generated challenge id invalid: {error}")))?;
    let challenge =
        arkret_wire::Base64UrlString::new(URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()))
            .map_err(|error| AppError::internal(format!("generated challenge invalid: {error}")))?;
    let service_id = state.service_resolution_commitment().full_id.clone();
    let origin = reqwest::Url::parse(&state.config().public_base_url)
        .map_err(|error| AppError::internal(format!("public base URL invalid: {error}")))?
        .origin()
        .ascii_serialization();
    let outcome = AgentProvisioningAbandonmentChallengeOutcome {
        request_id: body.request_id.clone(),
        challenge_id,
        challenge,
        purpose: "agent_provisioning_abandonment".to_owned(),
        account_subject: Hash::new(account_slot.account_subject)
            .map_err(|error| AppError::internal(format!("account subject invalid: {error}")))?,
        agent_id: body.agent_id.clone(),
        agent_slug,
        principal_control_realm_id: body.principal_control_realm_id.clone(),
        allocation_handle: body.allocation_handle.clone(),
        consequence_disclosure: vec![
            "declared_principal_control_realm_id_is_permanently_unusable".to_owned(),
            "agent_slug_is_released_for_reuse".to_owned(),
            "accepted_provision_event_stays_in_controller_pcr_history".to_owned(),
            "a_new_agent_must_be_provisioned_from_scratch".to_owned(),
        ],
        dpop_jkt: abandonment_dpop_jkt(&session)?,
        audience: service_id,
        origin,
        trust_domain: state.config().trust_domain.to_string(),
        issued_at,
        expires_at: issued_at
            + chrono::Duration::seconds(AGENT_PROVISIONING_ABANDONMENT_TTL_SECONDS),
    };
    let request_digest = abandonment_request_digest(&body)?;
    let stored = state
        .agent_pairings()
        .issue_provisioning_abandonment_challenge(
            &soland_storage::IssueAgentProvisioningAbandonmentChallenge {
                controller_id: session.actor.clone(),
                agent_id: body.agent_id.to_string(),
                principal_control_realm_id: body.principal_control_realm_id.to_string(),
                allocation_handle: body.allocation_handle.to_string(),
                request_digest,
                credential_fingerprint: abandonment_credential_fingerprint(&session),
                challenge_outcome: serde_json::to_value(&outcome).map_err(|error| {
                    AppError::internal(format!("abandonment challenge encode failed: {error}"))
                })?,
            },
        )
        .await
        .map_err(|error| {
            AppError::internal(format!("abandonment challenge persist failed: {error}"))
        })?;
    let value = abandonment_storage_error(stored, true)?;
    let outcome = serde_json::from_value(value).map_err(|error| {
        AppError::internal(format!("stored abandonment challenge invalid: {error}"))
    })?;
    json_ok(outcome)
}

#[endpoint(
    operation_id = "ak.self.agent.command.abandon_provisioning",
    summary = "Abandon an Agent provisioning",
    tags("agents")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.command.abandon_provisioning"))]
pub(super) async fn abandon_provisioning(
    aa: AuthArgs,
    body: JsonBody<AgentProvisioningAbandonmentRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentProvisioningAbandonmentOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let abandoned_at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
        chrono::Utc::now().timestamp_millis(),
    )
    .ok_or_else(|| AppError::internal("current abandonment timestamp is out of range"))?;
    let outcome = AgentProvisioningAbandonmentOutcome {
        request_id: body.request_id.clone(),
        status: "abandoned".to_owned(),
        agent_id: body.agent_id.clone(),
        principal_control_realm_id: body.principal_control_realm_id.clone(),
        abandoned_at,
    };
    let stored = state
        .agent_pairings()
        .confirm_provisioning_abandonment(&soland_storage::ConfirmAgentProvisioningAbandonment {
            controller_id: session.actor.clone(),
            agent_id: body.agent_id.to_string(),
            principal_control_realm_id: body.principal_control_realm_id.to_string(),
            allocation_handle: body.allocation_handle.to_string(),
            challenge_id: body.challenge_id.to_string(),
            challenge: body.challenge.to_string(),
            request_digest: abandonment_request_digest(&body)?,
            credential_fingerprint: abandonment_credential_fingerprint(&session),
            now: abandoned_at,
            terminal_outcome: serde_json::to_value(&outcome).map_err(|error| {
                AppError::internal(format!("abandonment outcome encode failed: {error}"))
            })?,
        })
        .await
        .map_err(|error| AppError::internal(format!("abandonment commit failed: {error}")))?;
    let value = abandonment_storage_error(stored, false)?;
    let outcome: AgentProvisioningAbandonmentOutcome =
        serde_json::from_value(value).map_err(|error| {
            AppError::internal(format!("stored abandonment outcome invalid: {error}"))
        })?;
    append_audit_log(
        state,
        Some(&session.actor),
        "ak.self.agent.command.abandon_provisioning",
        json!({
            "agent_id": &outcome.agent_id,
            "principal_control_realm_id": &outcome.principal_control_realm_id,
            "abandoned_at": outcome.abandoned_at,
        }),
        "accepted",
    )
    .await;
    json_ok(outcome)
}
/// `ak.self.agent.command.renew_pairing` — re-open pairing for a bootstrap or
/// a runtime-replacement agent (key-management.md §3.6.1). Both branches share
/// the one-time-handle invariant (the fresh `pairing_request_id` +
/// `pairing_code` replace the old tuple, which becomes permanently unresolvable
/// through the same anti-enumeration lookup; the PRINCIPAL is not one-time):
///
/// - Bootstrap re-open (never-keyed agent): the derived runtime_state returns to
///   `pending_runtime_key` without changing the lifecycle intent or Realm grants.
/// - Runtime replacement (agent already holds an active key, lifecycle `active` or `paused`): the
///   lifecycle intent, existing keys, sessions, and grants all stay untouched and runtime_state
///   projects `replacing`; completing the new pairing supersedes every old active key
///   (reason=`superseded_by_repairing`) in the pair transaction, preserving the lifecycle intent —
///   an `active` agent needs no resume.
///
/// Re-opening is never a lifecycle transition and never requires a forced
/// pause; `deactivated` is terminal.
#[endpoint(
    operation_id = "ak.self.agent.command.renew_pairing",
    summary = "Renew an agent's pairing",
    tags("agents")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.command.renew_pairing"))]
pub(super) async fn renew_agent_pairing(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<AgentRenewPairingRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentRenewPairingOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let agent_id = agent_id.into_inner();
    let body = body.into_inner();
    let record = require_agent_controller(state, &session, &agent_id).await?;
    // Lazy-expire first so a stale pending record renews through the same
    // state path as an observed-expired one.
    let record = lazily_expire_pairing(state, record).await?;
    crate::routing::identity::managed_agent_pcr::validate_agent_controller_binding(
        state,
        &record,
        chrono::Utc::now(),
    )
    .await?;
    if record.state == AgentLifecycleState::Deactivated {
        return Err(
            pairing_failed_precondition("agent is deactivated; deactivation is terminal")
                .with_reason_detail("agent_deactivated"),
        );
    }
    // Bootstrap re-open for a never-keyed agent; runtime replacement for one
    // that already holds an active authorized key (key-management.md §3.6.1).
    // Both active and paused agents replace in place with no forced pause — the
    // lifecycle intent is preserved and completing the pairing atomically
    // supersedes the old key.
    let bootstrap_reopen = record.authorized_event_ref.is_none();
    if !state.config().development_mode {
        return Err(AppError::unsupported_feature(
            "production agent pairing renewal requires protocol-valid delegated fan-out",
        )
        .with_wire_code("agent_provision_fanout_unavailable"));
    }
    let now_utc = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
        chrono::Utc::now().timestamp_millis(),
    )
    .ok_or_else(|| AppError::internal("current agent pairing timestamp is out of range"))?;
    // A never-keyed agent whose bootstrap window lapsed does not reserve the
    // slug, so a replacement agent may have claimed it since. Renewing would
    // then produce two open agents with the same selector slug for one
    // controller — reject like provision does.
    let agent_slug = record.agent_slug.clone().unwrap_or_default();
    if !agent_slug.is_empty() {
        let siblings = state
            .agent_pairings()
            .agents_for_controller(&session.actor)
            .await
            .map_err(|err| AppError::internal(format!("agent slug conflict check failed: {err}")))?
            .into_iter()
            .collect::<Vec<_>>();
        if siblings.iter().any(|sibling| {
            sibling.id != agent_id
                && sibling.agent_slug.as_deref() == Some(agent_slug.as_str())
                && agent_record_reserves_selector_slug(sibling, &now_utc)
        }) {
            return Err(pairing_failed_precondition(
                "slug is already bound to an active or open agent for this controller",
            ));
        }
    }
    let pairing_request_id =
        arkret_wire::OpaqueLocalId::new(format!("agent_pairing_request:{}", uuid::Uuid::now_v7()))
            .expect("generated pairing request id must be valid");
    let pairing_code = generate_pairing_code();
    let pairing_ttl_ms = body
        .pairing_ttl_ms
        .unwrap_or(15 * 60 * 1000)
        .min(12 * 60 * 60 * 1000);
    let expires_at = now_utc + chrono::Duration::milliseconds(pairing_ttl_ms as i64);
    let terminal_notification = account_notification_context(&record);
    let mut record = record;
    // Re-opening pairing is never a lifecycle transition (key-management.md
    // §3.6.1): the lifecycle intent stays exactly as it was and only the
    // derived runtime_state moves (to pending_runtime_key for bootstrap, or
    // replacing for runtime replacement) while the fresh handle is open.
    record.pairing_request_id = Some(pairing_request_id.clone());
    record.pairing_code = Some(pairing_code.clone());
    record.pairing_expires_at = Some(expires_at);
    // A runtime-key request submitted against the dead handle must not
    // survive into the renewed pairing.
    record.approval_request_id = None;
    record.runtime_key_request = None;
    record.approval_requested_at = None;
    record.runtime_key_binding_digest = None;
    record.runtime_public_key_digest = None;
    record.runtime_attestation_digest = None;
    record.pending_pairing_commit_intent = None;
    record.approval_notification_id = None;
    record.updated_at = now_utc;
    state
        .agent_pairings()
        .save_agent(record.clone())
        .await
        .map_err(|err| AppError::internal(format!("agent persist failed: {err}")))?;
    if let Some(context) = terminal_notification {
        persist_terminal_account_notification(
            state,
            context,
            arkret_models_collaboration::sync_frames::account_sync::AgentRuntimeApprovalRemovalReason::Renewed,
        )
        .await?;
    }
    append_audit_log(
        state,
        Some(&session.actor),
        "ak.self.agent.command.renew_pairing",
        json!({
            "agent_id": agent_id,
            "controller_id": session.actor,
            "slug": agent_slug,
            "pairing_request_id": pairing_request_id,
            "mode": if bootstrap_reopen { "bootstrap_reopen" } else { "runtime_replacement" },
        }),
        "accepted",
    )
    .await;
    let agent_principal_did = arkret_identifiers::DidCoreId::new(agent_id)
        .map_err(|err| AppError::internal(format!("persisted agent DID invalid: {err}")))?;
    let principal_control_realm_id = RealmId::new(record.principal_control_realm_id.clone())
        .map_err(|error| AppError::internal(format!("persisted Agent PCR invalid: {error}")))?;
    let controller_authorization_ref = record.controller_authorization_ref.clone();
    let pcr_recovery =
        crate::routing::identity::managed_agent_pcr::project_agent_pcr_recovery(state, &record)
            .await?;
    let requested_scope_digest =
        crate::routing::identity::managed_agent_pcr::requested_scope_digest_for_record(&record)?;
    json_ok(AgentRenewPairingOutcome {
        agent_id: agent_principal_did,
        principal_control_realm_id,
        controller_authorization_ref,
        requested_scope_digest,
        pcr_recovery,
        pairing_mode: if bootstrap_reopen {
            AgentPairingMode::Bootstrap
        } else {
            AgentPairingMode::Replacement
        },
        pairing_request_id,
        pairing_code: Some(pairing_code),
        expires_at,
    })
}

#[endpoint(
    operation_id = "ak.self.agent.read.list",
    summary = "List agents",
    tags("agents")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.read.list"))]
pub(super) async fn list_agents(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let records = state
        .agent_pairings()
        .agents_for_controller(&session.actor)
        .await
        .map_err(|err| AppError::internal(format!("agent list failed: {err}")))?
        .into_iter()
        .collect::<Vec<_>>();
    // Lazily expire any agent past its pairing window before projecting, so
    // the derived runtime_state reflects `pairing_expired` without changing the
    // lifecycle intent or Realm grants.
    let mut agents = Vec::with_capacity(records.len());
    for record in records {
        if !agent_record_is_materialized(&record) {
            continue;
        }
        let record = reconcile_accepted_agent_authorization(state, record).await?;
        let record = lazily_expire_pairing(state, record).await?;
        let runtime_state = agent_runtime_state_from_record(
            &record,
            agent_has_active_authorization(state, &record.id),
            chrono::Utc::now(),
        );
        agents.push(agent_projection_from_record(&record, runtime_state));
    }
    // spec `agent_list` = `{agents: [agent_projection], next_cursor?, has_more}`.
    json_ok(AgentList {
        agents,
        next_cursor: None,
        has_more: false,
    })
}

#[endpoint(
    operation_id = "ak.self.agent.resource.get",
    summary = "Get one agent",
    tags("agents")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.resource.get"))]
pub(super) async fn get_agent(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let service_authorized = agent_projection_service_authorized(state, req);
    let session = if service_authorized {
        None
    } else {
        Some(aa.authenticated_session(state, req).await?)
    };
    let agent_id = agent_id.into_inner();
    validate_agent_id(&agent_id)?;
    let record = state
        .agent_pairings()
        .agent(&agent_id)
        .await
        .map_err(|err| AppError::internal(format!("agent get failed: {err}")))?
        .ok_or_else(|| AppError::not_found("agent not found"))?;
    if !agent_record_is_materialized(&record) {
        return Err(AppError::not_found("agent not found"));
    }
    // Controller-self only: hide others' agents behind 404 to avoid enumeration.
    if let Some(session) = session.as_ref()
        && record.controller_id != session.actor
    {
        return Err(AppError::not_found("agent not found"));
    }
    let record = reconcile_accepted_agent_authorization(state, record).await?;
    let record = lazily_expire_pairing(state, record).await?;
    crate::routing::identity::managed_agent_pcr::validate_agent_controller_binding(
        state,
        &record,
        chrono::Utc::now(),
    )
    .await?;
    // The service-authorized caller is the Account Authority verifier, not a
    // public/runtime projection. It needs the authoritative pairing code to
    // reconstruct the runtime proof transcript during final approval. The
    // controller-facing pending approval projection remains secret-free.
    let mut view = agent_view_from_record(state, &record).await?;
    // Surface every durable, unrevoked grant so terminal deactivation can
    // author complete revocation coverage. The effective authz index supplies
    // optional display metadata, but pending or expired grants must not
    // disappear from the controller's revocation surface.
    let effective_grants = state
        .authorization()
        .grants_for_subject_all_realms(&agent_id)
        .into_iter()
        .map(|grant| {
            (
                (grant.grant_id, grant.realm_id),
                (grant.expires_at, "active".to_owned()),
            )
        })
        .collect::<BTreeMap<_, _>>();
    view.grants = state
        .projections()
        .snapshot()
        .unrevoked_grant_locations_for_subject(&agent_id)
        .into_iter()
        .filter_map(|(grant_id, realm_id)| {
            let display = effective_grants.get(&(grant_id.clone(), realm_id.clone()));
            Some(GrantSnapshot {
                grant_id: GrantId::new(grant_id).ok()?,
                realm_id: RealmId::new(realm_id).ok()?,
                status: display
                    .and_then(|(_, status)| arkret_wire::NonEmptyString::new(status.clone()).ok()),
                grant_digest: None,
                expires_at: display.and_then(|(expires_at, _)| *expires_at),
            })
        })
        .collect();
    json_ok(view)
}

/// Lazily clean up an agent whose open pairing window has elapsed. Pairing is
/// independent from the lifecycle intent and from Realm grants, so expiry never
/// changes the lifecycle, creates, revokes, or rewrites a grant; the derived
/// runtime_state simply falls to `pairing_expired` (never-keyed) or `ready`
/// (keyed) once the handle lapses (key-management.md §3.6.1).
pub(super) async fn lazily_expire_pairing(
    state: &AppState,
    mut record: AgentPrincipalRecord,
) -> Result<AgentPrincipalRecord, AppError> {
    if !agent_pairing_handle_is_open(&record) {
        return Ok(record);
    }
    let expired = record
        .pairing_expires_at
        .map(|expires| chrono::Utc::now() > expires)
        .unwrap_or(false);
    if !expired {
        return Ok(record);
    }
    let agent_id = record.id.clone();
    let terminal_notification = account_notification_context(&record);
    let now = chrono::Utc::now();
    // Pairing expiry is not a lifecycle transition (key-management.md §3.6.1):
    // the lifecycle intent is untouched, and the derived runtime_state falls to
    // pairing_expired (never-keyed) or ready (keyed) once the handle lapses.
    // Only the dead pending runtime-key request is cleaned up here.
    record.approval_request_id = None;
    record.runtime_key_request = None;
    record.approval_requested_at = None;
    record.runtime_key_binding_digest = None;
    record.runtime_public_key_digest = None;
    record.runtime_attestation_digest = None;
    record.approval_notification_id = None;
    record.updated_at = now;
    state
        .agent_pairings()
        .save_agent(record.clone())
        .await
        .map_err(|error| {
            AppError::internal(format!("failed to persist expired Agent pairing: {error}"))
        })?;
    if let Some(context) = terminal_notification
        && let Err(error) = persist_terminal_account_notification(
            state,
            context,
            arkret_models_collaboration::sync_frames::account_sync::AgentRuntimeApprovalRemovalReason::Expired,
        )
        .await
    {
        tracing::error!(message = %error.message, agent_id, "failed to persist expired Agent approval notification");
    }
    Ok(record)
}

pub(super) async fn lifecycle_transition(
    state: &AppState,
    session: &SessionRecord,
    agent_id: String,
    new_state: AgentLifecycleState,
    event_kind: &str,
    reason: Option<String>,
    sidecar_exposure_ack: Option<Value>,
    lifecycle_event: Option<arkret_wire::EventInitialSubmission>,
) -> Result<AgentLifecycleOutcome, AppError> {
    // Authentication is deliberately completed by the endpoint before this
    // helper is entered. A DPoP proof is single-use, so passing `AuthArgs` and
    // `Request` through here would verify the same proof twice and reject the
    // lifecycle command as a replay.
    let record = require_agent_controller(state, session, &agent_id).await?;
    let terminal_notification = (event_kind == "ak.self.agent.deactivate")
        .then(|| account_notification_context(&record))
        .flatten();
    let sidecar_exposure_ack =
        normalize_sidecar_exposure_ack(sidecar_exposure_ack, &session.actor)?;
    // Never synthesize an Agent-authored control Event from a session request.
    // Pause/resume carry the exact SDK-authored envelope. Deactivate remains
    // fail-closed until its request can carry the complete lifecycle + key +
    // grant revocation Event bundle atomically.
    let Some(lifecycle_event) = lifecycle_event else {
        if state.config().development_mode {
            return Err(AppError::unsupported_feature(
                "operation requires a controller-signed delegated SDK Event",
            )
            .with_wire_code("controller_signed_event_required"));
        }
        return Err(AppError::unsupported_feature(
            "production agent lifecycle transitions require protocol-valid delegated fan-out",
        )
        .with_wire_code("agent_lifecycle_fanout_unavailable"));
    };
    // Resume re-disclosure (key-management.md §3.6.1): sidecar circles the
    // controller created while the agent was paused re-enter the agent's
    // eligibility set on resume, so the controller MUST explicitly
    // re-acknowledge them; silent resume is forbidden.
    if event_kind == "ak.self.agent.resume" {
        // Resume is a pure lifecycle-intent write and MUST NOT interlock with an
        // open pairing handle (key-management.md §3.6.1): an in-flight
        // replacement handle keeps running across resume and closes only on
        // consumption or expiry.
        let paused_at = Some(record.updated_at);
        let new_sidecar_ids = controller_sidecars_since(state, &session.actor, paused_at);
        if !new_sidecar_ids.is_empty() {
            let acked: std::collections::BTreeSet<String> = sidecar_exposure_ack
                .as_ref()
                .and_then(|ack| ack.get("sidecar_refs"))
                .and_then(Value::as_array)
                .map(|refs| {
                    refs.iter()
                        .filter_map(Value::as_str)
                        .map(ToOwned::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            let missing: Vec<&String> = new_sidecar_ids
                .iter()
                .filter(|circle_id| !acked.contains(*circle_id))
                .collect();
            if !missing.is_empty() {
                return Err(AppError::new(
                    ErrorCode::FailedPrecondition,
                    format!(
                        "resume requires explicit sidecar exposure acknowledgement for {} sidecar circle(s) created while paused",
                        missing.len()
                    ),
                )
                .with_status(salvo::http::StatusCode::PRECONDITION_FAILED)
                .with_reason_code("sidecar_exposure_ack_required"));
            }
        }
    }
    let status_changed_at = chrono::Utc::now();
    // Read the current persisted state so the durable transition carries the
    // accurate `previous_status` (resume comes from `paused`, etc.).
    let previous_status = record.state;
    // Drive the FSM reducer with the exact durable
    // `ak.self.agent.{pause,resume,deactivate}` Event authored as the Agent and
    // executed/signed by its controller. Deactivate revocations are admitted
    // and rechecked by the endpoint before it calls this transition.
    let realm = record.principal_control_realm_id.clone();
    let authorization_ref = record.controller_authorization_ref.clone();
    submit_durable_agent_lifecycle(
        state,
        session,
        &realm,
        &agent_id,
        &authorization_ref,
        event_kind,
        previous_status.as_wire_str(),
        reason.as_deref(),
        sidecar_exposure_ack.as_ref(),
        lifecycle_event,
    )
    .await?;
    // Persist the lifecycle state transition on the agent_principal row so
    // list/get reflect the new status (the durable event drives the reducer
    // FSM; this row is the read-side projection consumed by the HTTP API).
    let mut updated_record = record;
    updated_record.state = new_state;
    updated_record.state_changed_at = Some(status_changed_at);
    updated_record.updated_at = status_changed_at;
    // Pause is a pure lifecycle-intent write and MUST NOT touch an open pairing
    // handle (key-management.md §3.6.1): pausing mid-replacement leaves the
    // handle live so the controller can still complete or let it expire.
    if event_kind == "ak.self.agent.deactivate" {
        updated_record.approval_request_id = None;
        updated_record.runtime_key_request = None;
        updated_record.approval_requested_at = None;
        updated_record.runtime_key_binding_digest = None;
        updated_record.runtime_public_key_digest = None;
        updated_record.runtime_attestation_digest = None;
        updated_record.approval_notification_id = None;
    }
    if matches!(
        new_state,
        AgentLifecycleState::Paused | AgentLifecycleState::Deactivated
    ) {
        sidecar::remove_agent_from_controller_sidecars(state, &session.actor, &agent_id).await?;
    }
    state
        .agent_pairings()
        .save_agent(updated_record)
        .await
        .map_err(|error| AppError::internal(format!("agent lifecycle persist failed: {error}")))?;
    if let Some(context) = terminal_notification {
        persist_terminal_account_notification(
            state,
            context,
            arkret_models_collaboration::sync_frames::account_sync::AgentRuntimeApprovalRemovalReason::Deactivated,
        )
        .await?;
    }
    // spec `agent_lifecycle_state` = `operation_status_outcome` =
    // `{ok: true, status}` (status is the post-transition `agent_status`).
    Ok(AgentLifecycleOutcome {
        ok: true,
        status: new_state,
    })
}

/// Active native Sidecars owned by `controller` created strictly
/// after `since`. `since=None` fails closed by treating every Sidecar as new,
/// forcing an explicit acknowledgement.
fn controller_sidecars_since(
    state: &AppState,
    controller: &str,
    since: Option<chrono::DateTime<chrono::Utc>>,
) -> Vec<String> {
    let projection = state.projections().snapshot();
    projection
        .sidecars
        .values()
        .filter(|sidecar| {
            sidecar.controller_id == controller
                && sidecar.state
                    == arkret_models_collaboration::agent_operations::AgentSidecarState::Active
                && since.is_none_or(|since| sidecar.created_at > since)
        })
        .map(|sidecar| sidecar.sidecar_id.clone())
        .collect()
}

#[endpoint(
    operation_id = "ak.self.agent.command.pause",
    summary = "Pause an agent",
    tags("agents")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.command.pause"))]
pub(super) async fn pause_agent(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<AgentPauseRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentLifecycleOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    json_ok(
        lifecycle_transition(
            state,
            &session,
            agent_id.into_inner(),
            AgentLifecycleState::Paused,
            "ak.self.agent.pause",
            body.reason.map(arkret_wire::NonEmptyString::into_string),
            None,
            Some(body.lifecycle_event),
        )
        .await?,
    )
}

#[endpoint(
    operation_id = "ak.self.agent.command.resume",
    summary = "Resume an agent",
    tags("agents")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.command.resume"))]
pub(super) async fn resume_agent(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<AgentResumeRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentLifecycleOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    json_ok(
        lifecycle_transition(
            state,
            &session,
            agent_id.into_inner(),
            AgentLifecycleState::Active,
            "ak.self.agent.resume",
            None,
            body.sidecar_exposure_ack
                .map(serde_json::to_value)
                .transpose()
                .map_err(|error| {
                    AppError::invalid_param(format!("sidecar_exposure_ack invalid: {error}"))
                })?,
            Some(body.lifecycle_event),
        )
        .await?,
    )
}

#[endpoint(
    operation_id = "ak.self.agent.command.deactivate",
    summary = "Deactivate an agent",
    tags("agents")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.command.deactivate"))]
pub(super) async fn deactivate_agent(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<AgentDeactivateRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentLifecycleOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let agent_id = agent_id.into_inner();
    let record = require_agent_controller(state, &session, &agent_id).await?;
    let body = body.into_inner();
    let reason = body.reason.as_deref();

    validate_durable_agent_lifecycle(
        &session,
        &record.principal_control_realm_id,
        &agent_id,
        &record.controller_authorization_ref,
        "ak.self.agent.deactivate",
        record.state.as_wire_str(),
        reason,
        None,
        &body.lifecycle_event.event,
    )?;

    // The final contract makes the accepted terminal lifecycle Event the
    // single atomic cascade boundary.  Key and grant invalidation is reducer
    // derived; accepting caller-supplied auxiliary revocation arrays created
    // a partial-deactivation state and has therefore been removed from wire.
    json_ok(
        lifecycle_transition(
            state,
            &session,
            agent_id,
            AgentLifecycleState::Deactivated,
            "ak.self.agent.deactivate",
            body.reason.map(arkret_wire::NonEmptyString::into_string),
            None,
            Some(body.lifecycle_event),
        )
        .await?,
    )
}

#[endpoint(
    operation_id = "ak.self.agent.grant.command.attach",
    summary = "Attach a grant to an agent",
    tags("agents")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.grant.command.attach"))]
pub(super) async fn attach_agent_grant(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    body: JsonBody<AgentGrantAttachRequestBody>,
    depot: &mut Depot,
    res: &mut Response,
    req: &mut Request,
) -> JsonResult<AgentGrantAttachOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let agent_id = agent_id.into_inner();
    let record = require_agent_controller(state, &session, &agent_id).await?;
    let body = body.into_inner();
    body.validate()
        .map_err(|error| AppError::invalid_param(error.to_string()))?;
    let grant_payload: arkret_models_collaboration::events_payloads::capability::CapabilityGrantPayload =
        body.grant_event
            .event
            .typed_payload::<arkret_wire::event_spec::CapabilityGrant>()
            .map_err(|error| AppError::invalid_param(error.to_string()))?;
    let grant = &grant_payload.grant;
    if !agent_grant_within_requested_scope(
        &record,
        &grant.actions,
        &grant.resources,
        &grant.constraints,
    ) {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "grant exceeds the immutable Agent requested_scope ceiling",
        )
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_wire_code("agent_grant_exceeds_requested_scope"));
    }
    let grant_id = GrantId::from_event_id(&body.grant_event.event.event_id);
    let realm_id = grant
        .realm_id
        .clone()
        .expect("validated Agent grant requires a Realm id");
    submit_signed_agent_event(state, &session, body.grant_event).await?;
    append_audit_log(
        state,
        Some(&session.actor),
        "ak.self.agent.grant.command.attach",
        json!({
            "agent_id": agent_id,
            "grant_id": grant_id,
            "realm_id": realm_id,
        }),
        "accepted",
    )
    .await;
    res.status_code(StatusCode::CREATED);
    // spec `agent_grant_attach_outcome` = `{ok, grant_id}`.
    json_ok(AgentGrantAttachOutcome { ok: true, grant_id })
}

#[endpoint(
    operation_id = "ak.self.agent.grant.resource.delete",
    summary = "Detach a grant from an agent",
    tags("agents")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.agent.grant.resource.delete"))]
pub(super) async fn detach_agent_grant(
    aa: AuthArgs,
    agent_id: PathParam<String>,
    grant_id: PathParam<String>,
    body: JsonBody<AgentGrantDetachRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AgentGrantDetachOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let agent_id = agent_id.into_inner();
    let grant_id = grant_id.into_inner();
    let record = require_agent_controller(state, &session, &agent_id).await?;
    crate::routing::identity::managed_agent_pcr::validate_agent_controller_binding(
        state,
        &record,
        chrono::Utc::now(),
    )
    .await?;
    let typed_grant_id = GrantId::new(grant_id.clone())
        .map_err(|error| AppError::invalid_param(format!("grant_id is invalid: {error}")))?;
    let body = body.into_inner();
    body.validate()
        .map_err(|error| AppError::invalid_param(error.to_string()))?;
    let payload = body
        .payload()
        .map_err(|error| AppError::invalid_param(error.to_string()))?;
    if payload.grant_id != typed_grant_id
        || payload
            .grant_ref
            .as_ref()
            .is_some_and(|grant_ref| grant_ref != &typed_grant_id)
    {
        return Err(AppError::invalid_param(
            "revoke_event payload grant_id/grant_ref must equal the path grant_id",
        ));
    }
    let locations = {
        let projection = state.projections().snapshot();
        projection
            .grant_locations_for_subject(&agent_id)
            .into_iter()
            .filter(|(candidate, _)| candidate == typed_grant_id.as_str())
            .collect::<Vec<_>>()
    };
    let [(matched_grant_id, realm_id)] = locations.as_slice() else {
        return Err(AppError::not_found("Agent capability grant not found"));
    };
    let event = &body.revoke_event.event;
    if event.actor_id.as_str() != session.actor
        || event.realm_id.as_str() != realm_id
        || matched_grant_id != typed_grant_id.as_str()
    {
        return Err(AppError::capability_denied(
            "revoke_event does not match the authenticated controller or target grant",
        ));
    }
    let revoked_at = event.created_at;
    submit_signed_agent_event(state, &session, body.revoke_event).await?;
    append_audit_log(
        state,
        Some(&session.actor),
        "ak.self.agent.grant.resource.delete",
        json!({
            "agent_id": agent_id,
            "grant_id": typed_grant_id,
            "realm_id": realm_id,
        }),
        "accepted",
    )
    .await;
    // spec `agent_grant_detach_outcome` = `{ok, revoked_at}`.
    json_ok(AgentGrantDetachOutcome {
        ok: true,
        revoked_at,
    })
}

#[cfg(test)]
mod deactivation_tests {
    use super::*;

    #[test]
    fn lifecycle_transition_contract_uses_a_pre_authenticated_session() {
        // This compile-time contract keeps the transition layer below the HTTP
        // authentication boundary. In particular, it must not regain access
        // to AuthArgs/Request and consume a single-use DPoP proof twice.
        async fn call_transition(state: &AppState, session: &SessionRecord) {
            let _ = lifecycle_transition(
                state,
                session,
                "did:web:agent.example".to_owned(),
                AgentLifecycleState::Paused,
                "ak.self.agent.pause",
                None,
                None,
                None,
            )
            .await;
        }

        let _ = call_transition;
    }
}
