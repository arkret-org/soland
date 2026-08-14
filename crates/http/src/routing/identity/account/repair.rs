//! Durable Direct Conversation replacement-repair source/target workflow.

use std::collections::BTreeMap;

use arkret_models_collaboration::direct_conversation_repair::{
    DirectConversationRepairEnqueueStatus, DirectConversationRepairRecipientTarget,
    DirectConversationRepairRelayRequest,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use soland_services::delivery::{
    DeviceMessageBatchCommitOutcome, DeviceMessageBatchInspection, DeviceMessageBatchItemRecord,
    DeviceMessageBatchRecord, DeviceMessageIntentRecord, DeviceMessageState,
    DeviceMessageTargetSnapshotGuard,
};

use super::*;

const SOURCE_INTENT_PREFIX: &str = "direct-conversation-repair-intent:";
const SOURCE_OUTCOME_PREFIX: &str = "direct-conversation-repair-outcome:";
const TARGET_REQUEST_DOMAIN: &[u8] = b"ak.member-repair-target-request-v1\n";
const HUMAN_SNAPSHOT_DOMAIN: &[u8] = b"ak.member-repair-target-snapshot-human-v1\n";
const AGENT_SNAPSHOT_DOMAIN: &[u8] = b"ak.member-repair-target-snapshot-agent-v1\n";
const MESSAGE_ID_DOMAIN: &[u8] = b"ak.member-repair-message-id-v1\n";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FrozenSourceIntent {
    state: String,
    destination_service_id: arkret_wire::DidCoreId,
    destination_trust_domain: String,
    destination_service_resolution:
        arkret_models_identity::identity_resolution::ServiceResolutionCarrier,
    relay: DirectConversationRepairRelayRequest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RepairBatchMarker {
    recipient_device_id: String,
    message_id: String,
    accepted_at: String,
}

pub(super) async fn dispatch(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<DirectConversationRepairDispatchRequest>,
) -> JsonResult<DirectConversationRepairEnqueueOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    body.validate_shape()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let requester = session_actor_core_id(&session.actor)?;
    if requester != body.content.requester_principal_id {
        return Err(AppError::capability_denied(
            "repair requester must equal the authenticated session principal",
        ));
    }
    let dispatch_digest = canonical_digest(&body, "repair dispatch")?;
    if let Some(outcome) = source_outcome(state, &requester, &body, &dispatch_digest).await? {
        return json_ok(outcome);
    }

    let intent_key = format!("{SOURCE_INTENT_PREFIX}{}", body.request_id);
    let (frozen, pre_resolved_route) = match state
        .jobs()
        .idempotency_record(requester.as_str(), &intent_key)
        .await
        .map_err(|error| AppError::internal(format!("repair intent lookup failed: {error}")))?
    {
        Some(record) => {
            require_same_digest(&record.request_hash, &dispatch_digest)?;
            (
                serde_json::from_value::<FrozenSourceIntent>(record.response_body).map_err(
                    |error| AppError::internal(format!("stored repair intent is invalid: {error}")),
                )?,
                None,
            )
        }
        None => {
            validate_direct_conversation_repair_state(state, &body).await?;
            validate_direct_conversation_repair_signature(state, &body).await?;
            validate_exact_requester_keypackage(state, &body).await?;
            let peer = repair_peer(state, &body).await?;
            let (destination_service_id, destination_service_resolution) =
                source_peer_delivery_binding(state, requester.as_str(), peer.as_str()).await?;
            let resolved_route = resolve_repair_route(
                state,
                &destination_service_id,
                &destination_service_resolution,
                None,
            )
            .await?;
            let destination_trust_domain = resolved_route.trust_domain.to_string();
            let frozen = FrozenSourceIntent {
                state: "relay_pending".to_owned(),
                destination_service_id,
                destination_trust_domain,
                destination_service_resolution,
                relay: DirectConversationRepairRelayRequest {
                    request_id: body.request_id.clone(),
                    content: body.content.clone(),
                    requester_authorization: body.requester_authorization.clone(),
                },
            };
            frozen
                .relay
                .validate_shape()
                .map_err(|error| AppError::param_invalid(error.to_string()))?;
            store_source_record(
                state,
                requester.as_str(),
                intent_key.clone(),
                dispatch_digest.clone(),
                StatusCode::SERVICE_UNAVAILABLE,
                serde_json::to_value(&frozen)
                    .map_err(|error| AppError::internal(error.to_string()))?,
            )
            .await?;
            let landed = state
                .jobs()
                .idempotency_record(requester.as_str(), &intent_key)
                .await
                .map_err(|error| {
                    AppError::internal(format!("repair intent verification failed: {error}"))
                })?
                .ok_or_else(|| AppError::internal("repair intent was not durably stored"))?;
            require_same_digest(&landed.request_hash, &dispatch_digest)?;
            (
                serde_json::from_value(landed.response_body).map_err(|error| {
                    AppError::internal(format!("stored repair intent is invalid: {error}"))
                })?,
                Some(resolved_route),
            )
        }
    };

    let outcome = relay_to_destination(state, &frozen, pre_resolved_route).await?;
    let outcome_key = format!("{SOURCE_OUTCOME_PREFIX}{}", body.request_id);
    store_source_record(
        state,
        requester.as_str(),
        outcome_key.clone(),
        dispatch_digest.clone(),
        StatusCode::OK,
        serde_json::to_value(&outcome).map_err(|error| AppError::internal(error.to_string()))?,
    )
    .await?;
    let landed = state
        .jobs()
        .idempotency_record(requester.as_str(), &outcome_key)
        .await
        .map_err(|error| AppError::internal(format!("repair outcome lookup failed: {error}")))?
        .ok_or_else(|| AppError::internal("repair outcome was not durably stored"))?;
    require_same_digest(&landed.request_hash, &dispatch_digest)?;
    let durable =
        serde_json::from_value::<DirectConversationRepairEnqueueOutcome>(landed.response_body)
            .map_err(|error| {
                AppError::internal(format!("stored repair outcome invalid: {error}"))
            })?;
    json_ok(durable)
}

async fn source_peer_delivery_binding(
    state: &AppState,
    requester: &str,
    peer: &str,
) -> Result<
    (
        arkret_wire::DidCoreId,
        arkret_models_identity::identity_resolution::ServiceResolutionCarrier,
    ),
    AppError,
> {
    let mut candidates = Vec::new();
    for (left, right) in [(requester, peer), (peer, requester)] {
        let Some(contact) = state
            .contacts()
            .contact_any(left, right)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
            .filter(|contact| {
                contact.status == "accepted"
                    && contact_has_scope_for_both(contact, "direct_message")
                    && accepted_contact_has_fact_refs(contact)
            })
        else {
            continue;
        };
        if let Some(binding) = contact_delivery_binding(&contact)? {
            candidates.push(binding);
        }
    }
    candidates.dedup();
    match candidates.as_slice() {
        [binding] => Ok(binding.clone()),
        [] => Err(delivery_binding_unresolvable(
            "accepted Contact has no peer delivery binding carrier",
        )),
        _ => Err(direct_repair_precondition(
            "accepted Contact peer delivery bindings conflict",
        )),
    }
}

fn contact_delivery_binding(
    contact: &ContactRecord,
) -> Result<
    Option<(
        arkret_wire::DidCoreId,
        arkret_models_identity::identity_resolution::ServiceResolutionCarrier,
    )>,
    AppError,
> {
    let (Some(service_id), Some(carrier)) = (
        contact.peer_service_id.as_deref(),
        contact.peer_service_resolution.as_ref(),
    ) else {
        return Ok(None);
    };
    let service_id = arkret_wire::DidCoreId::new(service_id.to_owned()).map_err(|error| {
        delivery_binding_unresolvable(format!("peer service core_id is invalid: {error}"))
    })?;
    let carrier = serde_json::from_value::<
        arkret_models_identity::identity_resolution::ServiceResolutionCarrier,
    >(carrier.clone())
    .map_err(|error| {
        delivery_binding_unresolvable(format!(
            "peer service resolution carrier is invalid: {error}"
        ))
    })?;
    Ok(Some((service_id, carrier)))
}

async fn validate_exact_requester_keypackage(
    state: &AppState,
    request: &DirectConversationRepairDispatchRequest,
) -> Result<(), AppError> {
    use soland_services::events::PersistedKeyPackageClaimState;

    let rows = state
        .mls_key_packages()
        .key_packages()
        .await
        .map_err(|error| AppError::internal(format!("KeyPackage lookup failed: {error}")))?;
    let row = rows
        .iter()
        .find(|row| row.keypackage_ref == request.content.requester_keypackage_ref.as_str())
        .ok_or_else(|| direct_repair_precondition("exact requester KeyPackage is unavailable"))?;
    let lifecycle = row
        .lifecycle()
        .map_err(|error| AppError::internal(format!("KeyPackage lifecycle invalid: {error}")))?;
    let authority_matches = match &request.requester_authorization {
        DirectConversationRepairAuthorization::Device {
            requester_device_id,
            device_authorize_event_id,
            ..
        } => {
            row.actor_id == request.content.requester_principal_id.as_str()
                && row.device_id == requester_device_id.as_str()
                && row.device_authorize_event_id.as_deref()
                    == Some(device_authorize_event_id.as_str())
                && row.agent_key_authorize_event_id.is_none()
        }
        DirectConversationRepairAuthorization::NativeAgent {
            requester_agent_id,
            agent_key_authorize_event_id,
            ..
        } => {
            row.actor_id == requester_agent_id.as_str()
                && row.agent_key_authorize_event_id.as_deref()
                    == Some(agent_key_authorize_event_id.as_str())
        }
    };
    if !authority_matches
        || row.last_resort
        || row.lifetime_not_after <= now().timestamp()
        || !matches!(
            lifecycle.claim_state,
            PersistedKeyPackageClaimState::Available
        )
    {
        return Err(direct_repair_precondition(
            "exact requester KeyPackage is not current and available",
        ));
    }
    Ok(())
}

async fn source_outcome(
    state: &AppState,
    requester: &DidCoreId,
    request: &DirectConversationRepairDispatchRequest,
    digest: &str,
) -> Result<Option<DirectConversationRepairEnqueueOutcome>, AppError> {
    let key = format!("{SOURCE_OUTCOME_PREFIX}{}", request.request_id);
    let Some(record) = state
        .jobs()
        .idempotency_record(requester.as_str(), &key)
        .await
        .map_err(|error| AppError::internal(format!("repair outcome lookup failed: {error}")))?
    else {
        return Ok(None);
    };
    require_same_digest(&record.request_hash, digest)?;
    let outcome = serde_json::from_value(record.response_body)
        .map_err(|error| AppError::internal(format!("stored repair outcome invalid: {error}")))?;
    Ok(Some(outcome))
}

async fn relay_to_destination(
    state: &AppState,
    frozen: &FrozenSourceIntent,
    pre_resolved_route: Option<soland_services::service_route::ResolvedServiceRoute>,
) -> Result<DirectConversationRepairEnqueueOutcome, AppError> {
    let route = match pre_resolved_route {
        Some(route) => route,
        None => {
            resolve_repair_route(
                state,
                &frozen.destination_service_id,
                &frozen.destination_service_resolution,
                Some(&frozen.destination_trust_domain),
            )
            .await?
        }
    };
    let endpoint = format!(
        "{}/_arkret/peer/direct-conversations/repair-relay",
        route.cache_entry.base_url.trim_end_matches('/')
    );
    let (endpoint, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        &endpoint,
        "Direct Conversation repair relay",
        state.config().development_mode,
        std::time::Duration::from_secs(20),
    )
    .map_err(|error| delivery_binding_unresolvable(error.to_string()))?;
    let bytes = arkret_canonical::canonical_json_bytes(&frozen.relay)
        .map_err(|error| AppError::internal(format!("repair relay encoding failed: {error}")))?;
    let local_service_id = local_service_core(state)?;
    let mut headers = reqwest::header::HeaderMap::new();
    crate::routing::federation::outbox::insert_header_if_valid(
        &mut headers,
        "content-type",
        "application/json",
    );
    crate::routing::federation::outbox::insert_header_if_valid(
        &mut headers,
        "content-digest",
        &crate::routing::federation::outbox::content_digest_header_value(&bytes),
    );
    crate::routing::federation::outbox::insert_header_if_valid(
        &mut headers,
        "source-service-id",
        local_service_id.as_str(),
    );
    crate::routing::federation::outbox::insert_header_if_valid(
        &mut headers,
        "destination-service-id",
        frozen.destination_service_id.as_str(),
    );
    crate::routing::federation::outbox::insert_header_if_valid(
        &mut headers,
        "source-trust-domain",
        state.config().trust_domain.as_str(),
    );
    crate::routing::federation::outbox::insert_header_if_valid(
        &mut headers,
        "destination-trust-domain",
        &frozen.destination_trust_domain,
    );
    crate::routing::federation::outbox::insert_header_if_valid(
        &mut headers,
        "idempotency-key",
        frozen.relay.request_id.as_str(),
    );
    let headers =
        crate::routing::federation::outbox::rfc9421_sign(state, headers, "POST", endpoint.as_str());
    let response = client
        .post(endpoint)
        .headers(headers)
        .body(bytes)
        .send()
        .await
        .map_err(|error| delivery_binding_unresolvable(error.to_string()))?;
    if response.status() == reqwest::StatusCode::CONFLICT {
        return Err(duplicate_conflict());
    }
    if !response.status().is_success() {
        return Err(delivery_binding_unresolvable(format!(
            "destination rejected repair relay with {}",
            response.status()
        )));
    }
    let outcome = response
        .json::<DirectConversationRepairEnqueueOutcome>()
        .await
        .map_err(|error| AppError::internal(format!("repair outcome decode failed: {error}")))?;
    let expected_digest = canonical_digest(&frozen.relay, "repair relay")?;
    if outcome.request_id != frozen.relay.request_id
        || outcome.request_digest.as_str() != expected_digest
        || outcome.destination_service_id.as_str() != frozen.destination_service_id.as_str()
        || outcome.validate_shape().is_err()
    {
        return Err(AppError::internal(
            "destination returned an inconsistent repair enqueue outcome",
        ));
    }
    Ok(outcome)
}

async fn resolve_repair_route(
    state: &AppState,
    service_id: &arkret_wire::DidCoreId,
    carrier: &arkret_models_identity::identity_resolution::ServiceResolutionCarrier,
    expected_trust_domain: Option<&str>,
) -> Result<soland_services::service_route::ResolvedServiceRoute, AppError> {
    let resolver = state
        .service_route_resolver()
        .map_err(delivery_binding_unresolvable)?;
    let route = match resolver
        .resolve_route(service_id, "principal_server", now(), false)
        .await
    {
        Ok(route) => route,
        Err(_) => resolver
            .resolve_carrier_route(carrier, service_id, "principal_server", now())
            .await
            .map_err(|error| delivery_binding_unresolvable(error.to_string()))?,
    };
    route
        .require_trust_domain(expected_trust_domain)
        .map_err(|error| delivery_binding_unresolvable(error.to_string()))?;
    Ok(route)
}

pub(in crate::routing) async fn accept_peer_relay(
    state: &AppState,
    source_service_id: &str,
    request: DirectConversationRepairRelayRequest,
) -> Result<DirectConversationRepairEnqueueOutcome, AppError> {
    request
        .validate_shape()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let request_digest = canonical_digest(&request, "repair relay")?;
    let request_key = target_request_key(source_service_id, request.request_id.as_str())?;
    let inspection = state
        .deliveries()
        .inspect_device_message_batch(&request_key, &request_digest, &[])
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    match inspection {
        DeviceMessageBatchInspection::Duplicate(outcomes) => {
            return target_outcome_from_markers(state, &request, &request_digest, &outcomes);
        }
        DeviceMessageBatchInspection::RequestConflict => return Err(duplicate_conflict()),
        DeviceMessageBatchInspection::MessageConflict { .. } => return Err(duplicate_conflict()),
        DeviceMessageBatchInspection::Fresh { .. } => {}
    }

    verify_peer_requester(state, &request).await?;
    let dispatch = request.dispatch_request();
    validate_direct_conversation_repair_state(state, &dispatch).await?;
    let recipient = repair_peer(state, &dispatch).await?;
    validate_peer_service_bindings(
        state,
        source_service_id,
        request.content.requester_principal_id.as_str(),
        recipient.as_str(),
    )
    .await?;
    if let Some(agent) = state
        .agent_pairings()
        .agent(recipient.as_str())
        .await
        .map_err(|error| AppError::internal(format!("repair recipient lookup failed: {error}")))?
    {
        return accept_agent_relay(
            state,
            source_service_id,
            &request,
            &request_key,
            &request_digest,
            &agent,
        )
        .await;
    }
    let mut devices = state
        .identities()
        .devices_for_actor(recipient.as_str())
        .await
        .map_err(|error| AppError::internal(format!("repair target snapshot failed: {error}")))?
        .into_iter()
        .filter(|device| device.revoked_at.is_none() && device.verification_state == "verified")
        .collect::<Vec<_>>();
    devices.sort_by(|left, right| left.device_id.cmp(&right.device_id));
    if devices.is_empty() {
        return Err(direct_repair_precondition(
            "repair recipient has no current authorized device",
        ));
    }

    let accepted_at = DateTime::<Utc>::from_timestamp_millis(now().timestamp_millis())
        .ok_or_else(|| AppError::internal("repair accepted_at is out of range"))?;
    let signed_at = match &request.requester_authorization {
        DirectConversationRepairAuthorization::Device { signed_at, .. }
        | DirectConversationRepairAuthorization::NativeAgent { signed_at, .. } => *signed_at,
    };
    let expires_at = signed_at + chrono::Duration::days(30);
    let sender_device_id = match &request.content.requester {
        MemberRepairRequester::Device {
            requester_device_id,
        } => requester_device_id.as_str(),
        MemberRepairRequester::NativeAgent {
            requester_agent_id, ..
        } => requester_agent_id.as_str(),
    };
    let accepted_at_text = arkret_canonical::format_timestamp_canonical(accepted_at);
    let mut items = Vec::with_capacity(devices.len());
    for device in &devices {
        let message_id = stable_message_id(
            source_service_id,
            request.request_id.as_str(),
            &device.device_id,
        );
        let marker = RepairBatchMarker {
            recipient_device_id: device.device_id.clone(),
            message_id: message_id.clone(),
            accepted_at: accepted_at_text.clone(),
        };
        let message_key = String::from_utf8(
            arkret_canonical::canonical_json_bytes(&marker)
                .map_err(|error| AppError::internal(error.to_string()))?,
        )
        .map_err(|error| AppError::internal(error.to_string()))?;
        let content = json!({
            "message_id": message_id,
            "kind": "ak.member.repair.request",
            "sender_device_id": sender_device_id,
            "expires_at": arkret_canonical::format_timestamp_canonical(expires_at),
            "content": request.content,
        });
        let intent_digest = canonical_digest(&content, "repair target message")?;
        items.push(DeviceMessageBatchItemRecord {
            message_key,
            intent_digest,
            idempotency_expires_at: expires_at + chrono::Duration::days(1),
            message: Some(DeviceMessageState {
                idempotency_key: request.request_id.to_string(),
                sender: request.content.requester_principal_id.to_string(),
                recipient: recipient.to_string(),
                device_id: device.device_id.clone(),
                position: state.next_to_device_position(),
                content,
                created_at: accepted_at,
            }),
        });
    }
    let intents = items
        .iter()
        .map(|item| DeviceMessageIntentRecord {
            message_key: item.message_key.clone(),
            intent_digest: item.intent_digest.clone(),
        })
        .collect::<Vec<_>>();
    // Catch a message-level collision before commit for a precise protocol
    // error; commit repeats the check atomically.
    if matches!(
        state
            .deliveries()
            .inspect_device_message_batch(&request_key, &request_digest, &intents)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?,
        DeviceMessageBatchInspection::RequestConflict
            | DeviceMessageBatchInspection::MessageConflict { .. }
    ) {
        return Err(duplicate_conflict());
    }
    crate::routing::events::test_chaos::pause_at(
        state,
        crate::routing::events::test_chaos::PRE_DIRECT_REPAIR_DEVICE_BATCH_COMMIT,
        request.request_id.as_str(),
    )
    .await;
    let outcome = state
        .deliveries()
        .commit_device_message_batch(DeviceMessageBatchRecord {
            request_key,
            request_digest: request_digest.clone(),
            idempotency_expires_at: expires_at + chrono::Duration::days(1),
            device_revocation_gate: None,
            target_snapshot_guard: Some(DeviceMessageTargetSnapshotGuard {
                recipient: recipient.to_string(),
                devices: devices
                    .iter()
                    .map(|device| (device.device_id.clone(), device.updated_at))
                    .collect(),
            }),
            items,
        })
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let outcomes = match outcome {
        DeviceMessageBatchCommitOutcome::Stored(outcomes)
        | DeviceMessageBatchCommitOutcome::Duplicate(outcomes) => outcomes,
        DeviceMessageBatchCommitOutcome::RequestConflict
        | DeviceMessageBatchCommitOutcome::MessageConflict { .. } => {
            return Err(duplicate_conflict());
        }
        DeviceMessageBatchCommitOutcome::SnapshotConflict => {
            return Err(direct_repair_precondition(
                "repair recipient device snapshot changed concurrently",
            ));
        }
        DeviceMessageBatchCommitOutcome::DeviceRevocationPending
        | DeviceMessageBatchCommitOutcome::DeviceRevoked => {
            return Err(AppError::internal(
                "server-authored repair batch unexpectedly carried a device revocation gate",
            ));
        }
    };
    target_outcome_from_markers(state, &request, &request_digest, &outcomes)
}

async fn validate_peer_service_bindings(
    _state: &AppState,
    _source_service_id: &str,
    _requester: &str,
    _recipient: &str,
) -> Result<(), AppError> {
    Err(direct_repair_precondition(
        "repair relay requires exact requester and recipient principal authority pairs",
    ))
}

async fn verify_peer_requester(
    state: &AppState,
    request: &DirectConversationRepairRelayRequest,
) -> Result<(), AppError> {
    let signing_input = request
        .dispatch_request()
        .signing_input()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    match &request.requester_authorization {
        DirectConversationRepairAuthorization::Device {
            requester_device_id,
            verification_method,
            device_authorize_event_id,
            signature,
            ..
        } => {
            let facet = crate::routing::identity::device_signing::try_resolve_device_signing_directory_facet(
                state,
                request.content.requester_principal_id.as_str(),
                requester_device_id.as_str(),
            )
            .await
            .map_err(|error| AppError::internal(format!("repair requester directory lookup failed: {error}")))?;
            if !matches!(
                facet.status,
                arkret_models_crypto::keys::DeviceStatus::Active
            ) || facet.device_authorize_event_id.as_ref() != Some(device_authorize_event_id)
                || !verification_method
                    .as_str()
                    .ends_with(&format!("#{}", requester_device_id))
            {
                return Err(direct_repair_precondition(
                    "repair requester device authorization is not current",
                ));
            }
            let key = facet
                .signing_key_did
                .as_deref()
                .and_then(|key| key.strip_prefix("did:key:"))
                .ok_or_else(|| direct_repair_precondition("repair requester key is invalid"))?;
            let key =
                crate::routing::identity::device_signing::decode_ed25519_key(key, "multibase")
                    .map_err(|_| direct_repair_precondition("repair requester key is invalid"))?;
            if !crate::routing::identity::device_signing::ed25519_verify(
                &key,
                &signing_input,
                signature.jws.as_str(),
            ) {
                return Err(direct_repair_precondition(
                    "repair requester signature is invalid",
                ));
            }
            Ok(())
        }
        DirectConversationRepairAuthorization::NativeAgent {
            requester_agent_id,
            verification_method,
            signature,
            ..
        } => {
            let controller = arkret_identity::verification_method_did(verification_method)
                .map_err(|_| {
                    direct_repair_precondition("repair requester Agent method is invalid")
                })?;
            if arkret_wire::project_full_id_to_core_id(&controller)
                .map_or(true, |id| id.as_str() != requester_agent_id.as_str())
            {
                return Err(direct_repair_precondition(
                    "repair requester Agent method does not match the requester",
                ));
            }
            let key = crate::jws_verify::resolve_ed25519_pubkey_async(
                state,
                verification_method.as_str(),
            )
            .await
            .map_err(|_| direct_repair_precondition("repair requester Agent key is unavailable"))?;
            if !crate::routing::identity::device_signing::ed25519_verify(
                &key,
                &signing_input,
                signature.jws.as_str(),
            ) {
                return Err(direct_repair_precondition(
                    "repair requester Agent signature is invalid",
                ));
            }
            Ok(())
        }
    }
}

async fn accept_agent_relay(
    state: &AppState,
    source_service_id: &str,
    request: &DirectConversationRepairRelayRequest,
    request_key: &str,
    request_digest: &str,
    agent: &soland_services::identity::AgentPairingState,
) -> Result<DirectConversationRepairEnqueueOutcome, AppError> {
    let runtime = agent
        .runtime_bindings()
        .map_err(|_| direct_repair_precondition("Agent runtime binding invalid"))?
        .active_binding
        .ok_or_else(|| {
            direct_repair_precondition("repair recipient has no current Agent runtime")
        })?;
    let accepted_at = DateTime::<Utc>::from_timestamp_millis(now().timestamp_millis())
        .ok_or_else(|| AppError::internal("repair accepted_at is out of range"))?;
    let signed_at = match &request.requester_authorization {
        DirectConversationRepairAuthorization::Device { signed_at, .. }
        | DirectConversationRepairAuthorization::NativeAgent { signed_at, .. } => *signed_at,
    };
    let expires_at = signed_at + chrono::Duration::days(30);
    let message_id = stable_message_id(
        source_service_id,
        request.request_id.as_str(),
        agent.id.as_str(),
    );
    let content = json!({
        "message_id": message_id,
        "kind": "ak.member.repair.request",
        "expires_at": arkret_canonical::format_timestamp_canonical(expires_at),
        "content": request.content,
    });
    let outcome = state
        .agent_pairings()
        .enqueue_runtime_message_if_current(&soland_storage::EnqueueAgentRuntimeMessage {
            request_key: request_key.to_owned(),
            request_digest: request_digest.to_owned(),
            snapshot: soland_storage::AgentRuntimeSnapshotGuard {
                agent_id: agent.id.clone(),
                verification_method: runtime.verification_method.to_string(),
                authorized_event_ref: runtime.authorized_event_ref.to_string(),
                updated_at: agent.updated_at,
            },
            content,
            enqueued_at: accepted_at,
        })
        .await
        .map_err(|error| AppError::internal(format!("Agent repair enqueue failed: {error}")))?;
    let record = match outcome {
        soland_storage::AgentRuntimeEnqueueOutcome::Stored(record)
        | soland_storage::AgentRuntimeEnqueueOutcome::Duplicate(record) => record,
        soland_storage::AgentRuntimeEnqueueOutcome::RequestConflict => {
            return Err(duplicate_conflict());
        }
        soland_storage::AgentRuntimeEnqueueOutcome::SnapshotConflict => {
            return Err(direct_repair_precondition(
                "repair recipient Agent runtime changed concurrently",
            ));
        }
    };
    let target_snapshot_digest = domain_hash(
        AGENT_SNAPSHOT_DOMAIN,
        &json!({
            "agent_id": record.agent_id,
            "verification_method": record.verification_method,
            "authorized_event_ref": record.authorized_event_ref,
            "message_id": record.message_id,
        }),
    )?;
    Ok(DirectConversationRepairEnqueueOutcome {
        request_id: request.request_id.clone(),
        request_digest: Hash::new(request_digest.to_owned())
            .map_err(|error| AppError::internal(error.to_string()))?,
        destination_service_id: local_service_core(state)?,
        status: DirectConversationRepairEnqueueStatus::Enqueued,
        recipient_target: DirectConversationRepairRecipientTarget::NativeAgent {
            target_snapshot_digest,
            enqueued_target_count: 1,
        },
        accepted_at: record.enqueued_at,
    })
}

async fn repair_peer(
    state: &AppState,
    request: &DirectConversationRepairDispatchRequest,
) -> Result<DidCoreId, AppError> {
    let binding = state
        .contacts()
        .settled_direct_binding_for_realm(request.content.realm_id.as_str())
        .filter(|binding| direct_binding_matches_projection(state, binding))
        .ok_or_else(|| direct_repair_precondition("Direct Conversation binding unavailable"))?;
    let peer = binding
        .participants_unordered
        .iter()
        .find(|participant| participant.as_str() != request.content.requester_principal_id.as_str())
        .ok_or_else(|| direct_repair_precondition("Direct Conversation peer unavailable"))?;
    DidCoreId::new(peer.clone())
        .map_err(|_| direct_repair_precondition("Direct Conversation peer core_id is invalid"))
}

fn target_outcome_from_markers(
    state: &AppState,
    request: &DirectConversationRepairRelayRequest,
    request_digest: &str,
    outcomes: &BTreeMap<String, bool>,
) -> Result<DirectConversationRepairEnqueueOutcome, AppError> {
    if outcomes.is_empty() || outcomes.values().any(|delivered| !delivered) {
        return Err(AppError::internal(
            "repair batch ledger contains an incomplete target outcome",
        ));
    }
    let mut markers = outcomes
        .keys()
        .map(|key| {
            serde_json::from_str::<RepairBatchMarker>(key).map_err(|error| {
                AppError::internal(format!("repair batch marker invalid: {error}"))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    markers.sort_by(|left, right| left.recipient_device_id.cmp(&right.recipient_device_id));
    let accepted_at = DateTime::parse_from_rfc3339(&markers[0].accepted_at)
        .map_err(|error| AppError::internal(format!("repair accepted_at invalid: {error}")))?
        .with_timezone(&Utc);
    if markers
        .iter()
        .any(|marker| marker.accepted_at != markers[0].accepted_at)
    {
        return Err(AppError::internal(
            "repair batch ledger has inconsistent acceptance timestamps",
        ));
    }
    let transcript = markers
        .iter()
        .map(|marker| {
            json!({
                "recipient_device_id": marker.recipient_device_id,
                "message_id": marker.message_id,
            })
        })
        .collect::<Vec<_>>();
    let snapshot_digest = domain_hash(HUMAN_SNAPSHOT_DOMAIN, &transcript)?;
    Ok(DirectConversationRepairEnqueueOutcome {
        request_id: request.request_id.clone(),
        request_digest: Hash::new(request_digest.to_owned())
            .map_err(|error| AppError::internal(error.to_string()))?,
        destination_service_id: local_service_core(state)?,
        status: DirectConversationRepairEnqueueStatus::Enqueued,
        recipient_target: DirectConversationRepairRecipientTarget::HumanPrincipal {
            target_snapshot_digest: snapshot_digest,
            enqueued_target_count: markers.len() as u64,
        },
        accepted_at,
    })
}

fn stable_message_id(source_service_id: &str, request_id: &str, device_id: &str) -> String {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(MESSAGE_ID_DOMAIN);
    hasher.update(source_service_id.as_bytes());
    hasher.update([0]);
    hasher.update(request_id.as_bytes());
    hasher.update([0]);
    hasher.update(device_id.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!("ak:device_message:{}", uuid::Uuid::from_bytes(bytes))
}

fn target_request_key(source_service_id: &str, request_id: &str) -> Result<String, AppError> {
    domain_hash(
        TARGET_REQUEST_DOMAIN,
        &json!({"source_service_id": source_service_id, "request_id": request_id}),
    )
    .map(|hash| hash.to_string())
}

fn domain_hash(domain: &[u8], value: &impl Serialize) -> Result<Hash, AppError> {
    let canonical = arkret_canonical::canonical_json_bytes(value)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let mut bytes = Vec::with_capacity(domain.len() + canonical.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&canonical);
    Hash::new(arkret_canonical::sha256_digest(bytes))
        .map_err(|error| AppError::internal(error.to_string()))
}

fn canonical_digest(value: &impl Serialize, label: &str) -> Result<String, AppError> {
    arkret_canonical::canonical_sha256(value)
        .map_err(|error| AppError::param_invalid(format!("{label} is not canonical: {error}")))
}

fn local_service_core(state: &AppState) -> Result<DidCoreId, AppError> {
    arkret_wire::project_full_id_to_core_id(&state.service_resolution_commitment().full_id)
        .map_err(|error| AppError::internal(format!("local service identity invalid: {error}")))
}

async fn store_source_record(
    state: &AppState,
    principal_id: &str,
    key: String,
    digest: String,
    status: StatusCode,
    response_body: Value,
) -> Result<(), AppError> {
    let created_at = now();
    state
        .jobs()
        .store_idempotency_record(soland_services::jobs::IdempotencyState {
            principal_id: principal_id.to_owned(),
            idempotency_key: key,
            service_id: state.service_id().clone(),
            request_hash: digest,
            response_status: status.as_u16() as i32,
            response_body,
            created_at,
            expires_at: created_at + chrono::Duration::days(30),
        })
        .await
        .map_err(|error| AppError::internal(format!("repair ledger write failed: {error}")))
}

fn require_same_digest(existing: &str, supplied: &str) -> Result<(), AppError> {
    if existing == supplied {
        Ok(())
    } else {
        Err(duplicate_conflict())
    }
}

fn duplicate_conflict() -> AppError {
    AppError::conflict("repair request_id was reused with different canonical content")
        .with_wire_code(arkret_wire::ErrorCode::DUPLICATE_CONFLICT)
}

fn delivery_binding_unresolvable(message: impl Into<String>) -> AppError {
    AppError::new(
        soland_http::error::ErrorCode::TemporarilyUnavailable,
        message.into(),
    )
    .with_status(StatusCode::SERVICE_UNAVAILABLE)
    .with_wire_code(arkret_wire::ErrorCode::DELIVERY_BINDING_UNRESOLVABLE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepted_contact_supplies_cross_service_resolution_carrier() {
        let service_id = "ak:did_core:webvh:z6mkpeer";
        let carrier = arkret_models_identity::identity_resolution::ServiceResolutionCarrier::CurrentRecordUrl {
            current_record_url: format!(
                "https://peer.example/_arkret/open/services/{service_id}/resolution"
            ),
            pinned_record_digest: None,
        };
        let now = Utc::now();
        let contact = ContactRecord {
            requester: "ak:did_core:webvh:z6mkrequester".to_owned(),
            target: "ak:did_core:webvh:z6mkpeerprincipal".to_owned(),
            contact_round_id: None,
            version: Some(1),
            granted_to_target_scopes: vec!["direct_message".to_owned()],
            granted_to_requester_scopes: vec!["direct_message".to_owned()],
            status: "accepted".to_owned(),
            request_event_ref: None,
            request_receipts: Vec::new(),
            request_mirror_receipts: Vec::new(),
            contact_round_evidence: None,
            contact_round_evidence_history: Vec::new(),
            control_outcomes: Vec::new(),
            response_event_ref: None,
            tombstone_event_ref: None,
            message: None,
            peer_service_id: Some(service_id.to_owned()),
            peer_service_resolution: Some(serde_json::to_value(&carrier).expect("carrier")),
            created_at: now,
            updated_at: now,
        };
        let (decoded_id, decoded_carrier) = contact_delivery_binding(&contact)
            .expect("valid contact carrier")
            .expect("binding present");
        assert_eq!(decoded_id.as_str(), service_id);
        assert_eq!(decoded_carrier, carrier);
    }
}
