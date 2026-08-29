use std::collections::{BTreeMap, BTreeSet};

use arkret_identifiers::{DidCoreId, EventId, RealmId};
use arkret_models_collaboration::account_lifecycle::{
    AccountStatusPropagationState, AccountStatusPublication, AccountStatusPublicationOutcome,
    AccountStatusPublicationRequestBody, AccountStatusPublicationStatus,
    AccountStatusReceiptedPublication, UnsignedAccountStatusReceipt,
};
use arkret_models_collaboration::event_query::{
    EventsQueryPostRequestBody, PeerEventsDescribeRequestBody, PeerEventsFrontierRequestBody,
    SealFrontierRequestBody,
};
use arkret_models_collaboration::event_sync::{
    EventsFrontierFederationPeerState, EventsSubmitFederationRequestBody, MAX_FEDERATED_EVENTS,
    PeerSealFrontierState, RealmSealFrontierView,
};
use arkret_models_collaboration::http_bodies::{
    EventsQueryOutcome, PeerEventsResolveOutcome, PeerEventsResolveRequestBody,
};
use arkret_models_collaboration::principal_operations::{
    PcrGenesisSubmitOutcome, PcrGenesisSubmitRequestBody,
};
use arkret_models_identity::service_identity::{CanonicalServiceUrl, ServiceRegistrationKey};
use arkret_wire::{ServiceKind, SignalRelayOutcome, SignalRelayRequest};
use chrono::{DateTime, Duration, Utc};
use salvo::http::StatusCode;
use salvo::prelude::*;
use serde::Serialize;
use serde_json::{Value, json};
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};
use soland_services::events::{
    AcceptedEvent, PeerEventsPageQuery, RealmMetadata as RealmMetaRecord,
};

use super::{
    is_realm_deleted, is_valid_hash_digest, now, query_param, render_error, sha256_hex,
    validate_did,
};
use crate::state::AppState;

const HEADER_SOURCE_SERVICE_ID: &str = "source-service-id";
const HEADER_DESTINATION_SERVICE_ID: &str = "destination-service-id";
const MAX_PEER_EVENTS_READ_LIMIT: usize = 100;
const MAX_PEER_EVENTS_RESOLVE: usize = 1024;

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
struct PeerEventsDescribeLimits {
    max_batch_item_count: usize,
    max_query_limit: usize,
    max_resolve: usize,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
struct PeerSnapshotHeadOutcome {}

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("events/describe").query(peer_events_describe))
        .push(
            Router::with_path("events")
                .post(peer_events_submit)
                .query(peer_events_read_body),
        )
        .push(Router::with_path("events/resolve").query(peer_events_resolve))
        .push(Router::with_path("events/frontier").query(peer_events_frontier))
        .push(Router::with_path("seals/frontier").query(peer_seals_frontier))
        .push(Router::with_path("principal-genesis").post(peer_principal_genesis))
        .push(Router::with_path("account-status").post(peer_account_status_submit))
        .push(Router::with_path("snapshot/head").get(peer_snapshot_head))
        .push(
            Router::with_path("device-revocations/check")
                .post(super::peer_device_revocations::check_device_revocation_gate),
        )
        .push(Router::with_path("signal").post(peer_signal_relay))
}

#[salvo::oapi::endpoint(
    operation_id = "ak.peer.principal_genesis.command.submit",
    tags("events")
)]
#[tracing::instrument(skip_all, fields(op = "ak.peer.principal_genesis.command.submit.v1"))]
async fn peer_principal_genesis(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PcrGenesisSubmitOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    validate_peer_request(state, req, true).await?;
    let source_id = source_id_from_request(req)?;
    let source_trust_domain = required_header(req, "source-trust-domain")?;
    let header_idempotency_key = required_header(req, "idempotency-key")?;
    let request = parse_json_body::<PcrGenesisSubmitRequestBody>(
        req,
        "invalid ak.peer.principal_genesis.command.submit.v1 request body",
    )
    .await?;
    request
        .validate()
        .map_err(|error| schema_violation(error.to_string()))?;
    let configured_authority = trusted_account_authority_id(state).await?;
    if source_id != request.account_authority_id.as_str()
        || configured_authority != request.account_authority_id
    {
        return Err(AppError::capability_denied(
            "PCR genesis relay source is not the configured Account Authority",
        ));
    }
    if header_idempotency_key != request.idempotency_key.as_str()
        || source_trust_domain
            != request
                .identity_creation_control_proof
                .trust_domain
                .as_str()
    {
        return Err(cross_domain_replay(
            "PCR genesis relay transport binding mismatch",
        ));
    }
    if let Some(authority_url) = state.config().account_authority_url.as_deref()
        && request
            .identity_creation_control_proof
            .origin
            .as_str()
            .trim_end_matches('/')
            != authority_url.trim_end_matches('/')
    {
        return Err(cross_domain_replay(
            "PCR genesis creation-proof origin does not match the configured Account Authority",
        ));
    }
    super::event_log::submit_peer_pcr_genesis(state, &request)
        .await
        .map_err(|error| {
            AppError::internal(error.message)
                .with_status(error.status)
                .with_wire_code(error.code)
        })
        .and_then(json_ok)
}

async fn trusted_account_authority_binding(
    state: &AppState,
) -> Result<(DidCoreId, CanonicalServiceUrl), AppError> {
    let authority_url = state
        .config()
        .account_authority_url
        .as_deref()
        .ok_or_else(|| AppError::capability_denied("Account Authority is not configured"))?;
    let registration_key = ServiceRegistrationKey::new(
        ServiceKind::AuthServer,
        CanonicalServiceUrl::canonicalize(authority_url).map_err(|error| {
            AppError::internal(format!(
                "configured Account Authority URL is invalid: {error}"
            ))
        })?,
    )
    .map_err(|error| AppError::internal(error.to_string()))?;
    let registration = state
        .dids()
        .service_registration(&registration_key)
        .await
        .map_err(|error| {
            AppError::new(
                soland_http::error::ErrorCode::TemporarilyUnavailable,
                format!("Account Authority service registration is unavailable: {error}"),
            )
        })?
        .ok_or_else(|| {
            AppError::capability_denied(
                "Account Authority URL has no accepted service identity registration",
            )
        })?;
    registration
        .validate_for(&registration_key)
        .map_err(|error| {
            AppError::capability_denied(format!(
                "Account Authority service identity registration is invalid: {error}"
            ))
        })?;
    let registered_id =
        arkret_wire::project_did_to_core_id(registration.did()).map_err(|error| {
            AppError::internal(format!(
                "registered Account Authority DID cannot be projected: {error}"
            ))
        })?;
    if let Some(configured_id) = state.config().account_authority_id.as_deref() {
        let configured_id = DidCoreId::new(configured_id.to_owned()).map_err(|error| {
            AppError::internal(format!(
                "configured Account Authority service identity is invalid: {error}"
            ))
        })?;
        if configured_id != registered_id {
            return Err(AppError::capability_denied(
                "accepted Account Authority service registration does not match the configured service identity pin",
            ));
        }
    }
    Ok((registered_id, registration_key.public_base_url().clone()))
}

pub(crate) async fn trusted_account_authority_id(state: &AppState) -> Result<DidCoreId, AppError> {
    trusted_account_authority_binding(state)
        .await
        .map(|(service_id, _)| service_id)
}

#[salvo::oapi::endpoint(operation_id = "ak.peer.account_status.command.submit", tags("events"))]
async fn peer_account_status_submit(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AccountStatusPublicationOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    validate_peer_request(state, req, true).await?;
    let source_id = source_id_from_request(req)?;
    let idempotency_key = required_header(req, "idempotency-key")?;
    let request = parse_json_body::<AccountStatusPublicationRequestBody>(
        req,
        "invalid ak.peer.account_status.command.submit.v1 request body",
    )
    .await?;
    request
        .validate_shape()
        .map_err(|error| schema_violation(error.to_string()))?;
    let record = request.publication.record();
    validate_account_status_publication(state, &source_id, &request).await?;
    let request_hash = arkret_canonical::canonical_sha256(&request).map_err(|error| {
        AppError::internal(format!("account-status request digest failed: {error}"))
    })?;
    let idempotency_principal_id = arkret_wire::DidCoreId::new(source_id.clone())
        .map_err(|error| AppError::param_invalid(format!("Source-Service-ID invalid: {error}")))?;
    if let Some(stored) = state
        .jobs()
        .idempotency_record(&idempotency_principal_id, &idempotency_key)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    {
        if stored.request_hash != request_hash {
            return Err(AppError::conflict(
                "Idempotency-Key reused with another account-status publication",
            )
            .with_wire_code("duplicate_conflict"));
        }
        let outcome = serde_json::from_value(stored.response_body).map_err(|error| {
            AppError::internal(format!("stored account-status outcome invalid: {error}"))
        })?;
        return json_ok(outcome);
    }

    let candidate_receipt = sign_account_status_receipt(state, record)?;
    let append = state
        .persistence()
        .append_account_status_record(record, &candidate_receipt)
        .await
        .map_err(|error| {
            AppError::internal(format!("account-status replica unavailable: {error}"))
        })?;
    let (status, current, required_status_seq, receipt) = match append {
        soland_storage::AccountStatusReplicaAppend::Accepted(receipt) => (
            AccountStatusPublicationStatus::Accepted,
            Some(record.clone()),
            None,
            receipt,
        ),
        soland_storage::AccountStatusReplicaAppend::Duplicate(receipt) => (
            AccountStatusPublicationStatus::Duplicate,
            Some(record.clone()),
            None,
            receipt,
        ),
        soland_storage::AccountStatusReplicaAppend::DependencyMissing {
            current_record,
            required_status_seq,
        } => {
            let outcome = publication_outcome(
                record,
                AccountStatusPublicationStatus::DependencyMissing,
                current_record.as_ref(),
                Some(required_status_seq),
                None,
            );
            return json_ok(outcome);
        }
        soland_storage::AccountStatusReplicaAppend::Stale { current_record } => {
            return Err(AppError::new(
                soland_http::error::ErrorCode::FailedPrecondition,
                format!(
                    "account-status record is stale; current status_seq is {}",
                    current_record.status_seq
                ),
            )
            .with_reason_code(arkret_wire::ReasonCode::ACCOUNT_STATUS_RECORD_STALE));
        }
        soland_storage::AccountStatusReplicaAppend::Conflict { kind, .. } => {
            use soland_storage::AccountStatusReplicaConflictKind;
            return Err(match kind {
                AccountStatusReplicaConflictKind::Fork => AppError::new(
                    soland_http::error::ErrorCode::FailedPrecondition,
                    "account-status ledger fork",
                )
                .with_reason_code(arkret_wire::ReasonCode::ACCOUNT_STATUS_RECORD_FORK),
                AccountStatusReplicaConflictKind::BindingRollback => AppError::new(
                    soland_http::error::ErrorCode::FailedPrecondition,
                    "account-status binding version rollback",
                )
                .with_reason_code(arkret_wire::ReasonCode::ACCOUNT_STATUS_BINDING_ROLLBACK),
                AccountStatusReplicaConflictKind::TransitionInvalid => AppError::new(
                    soland_http::error::ErrorCode::FailedPrecondition,
                    "account-status transition is invalid",
                )
                .with_reason_code(arkret_wire::ReasonCode::ACCOUNT_STATUS_TRANSITION_INVALID),
                AccountStatusReplicaConflictKind::ErasurePendingTerminal => AppError::new(
                    soland_http::error::ErrorCode::FailedPrecondition,
                    "account-status erasure_pending state is terminal",
                )
                .with_reason_code(arkret_wire::ReasonCode::ERASURE_PENDING_IS_TERMINAL),
            });
        }
    };
    if status == AccountStatusPublicationStatus::Accepted
        && record.status
            == arkret_models_collaboration::objects::account_status::AccountStatus::ErasurePending
    {
        crate::account_erasure_worker::ensure_intent(
            state,
            record.account_authority_id.as_str(),
            record.account_id.as_str(),
            &record.principal_authority.principal_id,
            &record.account_status_record_id,
        )
        .await?;
    }
    let (propagation_state, pending_destination_count) =
        enqueue_account_status_fanout(state, record, &receipt).await?;
    let outcome = AccountStatusPublicationOutcome {
        status,
        account_status_record_id: record.account_status_record_id.clone(),
        status_seq: record.status_seq,
        account_id: record.account_id.clone(),
        current_account_status_record_id: current
            .as_ref()
            .map(|record| record.account_status_record_id.clone()),
        current_status_seq: current.as_ref().map(|record| record.status_seq),
        required_status_seq,
        barrier_cursor: None,
        propagation_state,
        pending_destination_count,
        receipt: Some(receipt),
    };
    let stored_at = Utc::now();
    state
        .jobs()
        .store_idempotency_record(soland_services::jobs::IdempotencyState {
            principal_id: idempotency_principal_id,
            idempotency_key,
            service_id: state.service_core_id(),
            request_hash,
            response_status: StatusCode::OK.as_u16() as i32,
            response_body: serde_json::to_value(&outcome)
                .map_err(|error| AppError::internal(error.to_string()))?,
            created_at: stored_at,
            expires_at: stored_at + Duration::days(3650),
        })
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(outcome)
}

async fn enqueue_account_status_fanout(
    state: &AppState,
    record: &arkret_models_collaboration::account_lifecycle::AccountStatusRecord,
    receipt: &arkret_models_collaboration::account_lifecycle::AccountStatusReceipt,
) -> Result<(AccountStatusPropagationState, Option<u64>), AppError> {
    if record.principal_authority.principal_server_id.as_str() != state.service_id() {
        return Ok((AccountStatusPropagationState::NotRequired, None));
    }
    let targets =
        crate::routing::identity::account::lifecycle::deactivation_peer_service_targets_for_actor(
            state,
            record.principal_authority.principal_id.as_str(),
        );
    if targets.len() > 256 {
        return Err(AppError::internal(
            "account-status affected Principal Server set exceeds 256",
        ));
    }
    if targets.is_empty() {
        return Ok((AccountStatusPropagationState::Complete, Some(0)));
    }
    let configured = crate::routing::federation::federation::configured_peer_targets(state)
        .into_iter()
        .map(|peer| (peer.service_id.clone(), peer))
        .collect::<BTreeMap<_, _>>();
    let body = AccountStatusPublicationRequestBody {
        publication: AccountStatusPublication::Receipted(AccountStatusReceiptedPublication {
            record: record.clone(),
            account_status_receipts: vec![receipt.clone()],
        }),
    };
    let payload = arkret_canonical::canonical_json_string(&body)
        .map_err(|error| AppError::internal(format!("account-status fanout encode: {error}")))?;
    let mut unresolved = false;
    for target in &targets {
        let Some(service_id) = target.get("service_id").and_then(Value::as_str) else {
            return Err(AppError::internal(
                "account-status affected-service projection has no service_id",
            ));
        };
        let Some(peer) =
            configured.get(&arkret_wire::DidCoreId::new(service_id.to_owned()).map_err(
                |error| AppError::internal(format!("affected service id is invalid: {error}")),
            )?)
        else {
            unresolved = true;
            continue;
        };
        crate::routing::federation::outbox::enqueue_coalesced_outbound(
            state,
            &peer.url,
            peer.service_id.as_str(),
            "/_arkret/peer/account-status",
            &format!(
                "account-status:{}:{}:{}:{}",
                record.account_authority_id,
                record.account_id,
                peer.service_id,
                record.account_status_record_id,
            ),
            &payload,
            &format!(
                "account-status:{}:{}",
                record.account_authority_id, record.account_id,
            ),
            i64::try_from(record.status_seq).map_err(|_| {
                AppError::internal("account-status sequence exceeds outbox lane range")
            })?,
        )
        .await
        .map_err(|error| AppError::internal(format!("account-status fanout enqueue: {error}")))?;
    }
    Ok((
        if unresolved {
            AccountStatusPropagationState::Incomplete
        } else {
            AccountStatusPropagationState::Scheduled
        },
        Some(targets.len() as u64),
    ))
}

fn publication_outcome(
    record: &arkret_models_collaboration::account_lifecycle::AccountStatusRecord,
    status: AccountStatusPublicationStatus,
    current: Option<&arkret_models_collaboration::account_lifecycle::AccountStatusRecord>,
    required_status_seq: Option<u64>,
    receipt: Option<arkret_models_collaboration::account_lifecycle::AccountStatusReceipt>,
) -> AccountStatusPublicationOutcome {
    AccountStatusPublicationOutcome {
        status,
        account_status_record_id: record.account_status_record_id.clone(),
        status_seq: record.status_seq,
        account_id: record.account_id.clone(),
        current_account_status_record_id: current
            .map(|record| record.account_status_record_id.clone()),
        current_status_seq: current.map(|record| record.status_seq),
        required_status_seq,
        barrier_cursor: None,
        propagation_state: AccountStatusPropagationState::NotRequired,
        pending_destination_count: None,
        receipt,
    }
}

fn sign_account_status_receipt(
    state: &AppState,
    record: &arkret_models_collaboration::account_lifecycle::AccountStatusRecord,
) -> Result<arkret_models_collaboration::account_lifecycle::AccountStatusReceipt, AppError> {
    let accepted_at = Utc::now();
    let unsigned = UnsignedAccountStatusReceipt {
        receipt_id: arkret_wire::ReceiptId::new(crate::ids::generate("receipt"))
            .map_err(|error| AppError::internal(error.to_string()))?,
        account_status_record_id: record.account_status_record_id.clone(),
        record_digest: record
            .payload_digest()
            .map_err(|error| AppError::internal(error.to_string()))?,
        account_authority_id: record.account_authority_id.clone(),
        account_id: record.account_id.clone(),
        status_seq: record.status_seq,
        receiver_id: DidCoreId::new(state.service_id().clone())
            .map_err(|error| AppError::internal(error.to_string()))?,
        accepted_at,
        verification_method: state
            .service_verification_method("notary-key")
            .map_err(AppError::internal)?,
    };
    arkret_signatures::account_status::sign_account_status_receipt(
        unsigned,
        state.notary_signing_key().as_ref(),
    )
    .map_err(|error| AppError::internal(format!("account-status receipt signing failed: {error}")))
}

async fn historical_account_status_service_key(
    state: &AppState,
    service_id: &DidCoreId,
    service_kind: ServiceKind,
    verification_method: &str,
    at: chrono::DateTime<chrono::Utc>,
    label: &str,
) -> Result<ed25519_dalek::VerifyingKey, AppError> {
    crate::jws_verify::validate_verification_method_controller(
        service_id.as_str(),
        verification_method,
    )
    .map_err(|error| {
        AppError::capability_denied(format!(
            "account-status {label} method controller mismatch: {error}"
        ))
    })?;
    let method = arkret_wire::DidUrl::new(verification_method.to_owned()).map_err(|error| {
        schema_violation(format!(
            "account-status {label} verification method invalid: {error}"
        ))
    })?;
    let base_url = if service_kind == ServiceKind::AuthServer {
        let (registered_id, registered_base_url) = trusted_account_authority_binding(state).await?;
        if registered_id != *service_id {
            return Err(AppError::capability_denied(format!(
                "account-status {label} service identity does not match the accepted Account Authority registration"
            )));
        }
        registered_base_url.as_str().to_owned()
    } else {
        crate::routing::federation::federation::resolved_peer_base_url(
            state,
            service_id.as_str(),
            service_kind.as_str(),
            false,
        )
        .await
        .map_err(|error| {
            AppError::capability_denied(format!(
                "account-status {label} authenticated route resolution failed: {error}"
            ))
        })?
    };
    let evidence = crate::routing::identity::agents::evidence::fetch_service_signer_evidence(
        state,
        service_id,
        Some(&base_url),
        Some(&method),
        at,
    )
    .await
    .map_err(|error| {
        AppError::capability_denied(format!(
            "account-status {label} historical signer evidence unavailable: {error:?}"
        ))
    })?;
    let arkret_models_identity::AuthenticatedSignerResolutionEvidence::Service {
        authenticated_resolution,
        ..
    } = evidence
    else {
        return Err(AppError::capability_denied(format!(
            "account-status {label} signer evidence is not service evidence"
        )));
    };
    let document = arkret_identity::authenticated_service_document_at(
        &authenticated_resolution,
        service_id,
        at,
    )
    .map_err(|error| {
        AppError::capability_denied(format!(
            "account-status {label} historical service document invalid: {error}"
        ))
    })?;
    arkret_identity::jws::resolve_ed25519_pubkey_from_document(&document, verification_method)
        .map_err(|error| {
            AppError::capability_denied(format!(
                "account-status {label} historical key unavailable: {error}"
            ))
        })
}

async fn validate_account_status_publication(
    state: &AppState,
    source_id: &str,
    request: &AccountStatusPublicationRequestBody,
) -> Result<(), AppError> {
    let record = request.publication.record();
    record
        .validate_shape()
        .map_err(|error| schema_violation(error.to_string()))?;
    let configured = trusted_account_authority_id(state).await?;
    if configured != record.account_authority_id {
        return Err(AppError::capability_denied(
            "account-status record Account Authority mismatch",
        ));
    }
    let local_server = DidCoreId::new(state.service_id().clone())
        .map_err(|error| AppError::internal(error.to_string()))?;
    let method = record.proof.verification_method.as_str();
    let public_key = historical_account_status_service_key(
        state,
        &record.account_authority_id,
        ServiceKind::AuthServer,
        method,
        record.proof.created_at,
        "Account Authority",
    )
    .await?;
    arkret_signatures::account_status::verify_account_status_record(
        record,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: public_key.to_bytes().to_vec(),
        },
    )
    .map_err(|error| {
        AppError::capability_denied(format!("account-status authority proof invalid: {error}"))
    })?;

    if source_id != record.account_authority_id.as_str() {
        if source_id != record.principal_authority.principal_server_id.as_str() {
            return Err(AppError::capability_denied(
                "account-status fanout source is not the origin Principal Server",
            ));
        }
        let source_receipt = request
            .publication
            .receipts()
            .iter()
            .find(|receipt| receipt.receiver_id.as_str() == source_id)
            .ok_or_else(|| {
                AppError::capability_denied(
                    "account-status fanout omits the origin Principal Server receipt",
                )
            })?;
        let receipt_method = source_receipt.proof.verification_method.as_str();
        let receipt_key = historical_account_status_service_key(
            state,
            &source_receipt.receiver_id,
            ServiceKind::PrincipalServer,
            receipt_method,
            source_receipt.accepted_at,
            "receipt issuer",
        )
        .await?;
        arkret_signatures::account_status::verify_account_status_receipt(
            source_receipt,
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: receipt_key.to_bytes().to_vec(),
            },
        )
        .map_err(|error| {
            AppError::capability_denied(format!("account-status receipt proof invalid: {error}"))
        })?;
        return Ok(());
    }

    if record.principal_authority.principal_server_id != local_server {
        return Err(AppError::capability_denied(
            "initial account-status record is addressed to another Principal Server",
        ));
    }

    let authority = arkret_wire::PrincipalAuthorityKey::new(
        record.principal_authority.principal_id.clone(),
        local_server,
    );
    let resolution = state
        .persistence()
        .principal_resolution_by_authority_key(&authority)
        .await
        .map_err(|error| {
            AppError::internal(format!("account-status PCR binding unavailable: {error}"))
        })?
        .ok_or_else(|| AppError::capability_denied("account-status PCR binding is not accepted"))?;
    // `account_id` is the Account Authority's own deployment-local service
    // account id (account-lifecycle.md §3.1); a Principal Server never mints or
    // stores it, so it can only be bound to the Event payload and to the
    // monotonic authority floor below. The local `AccountRecord.id` is an
    // unrelated soland-local identifier and comparing the two rejects every
    // lawful publication.
    if resolution.pcr_realm_id != record.principal_control_realm_id {
        return Err(AppError::capability_denied(
            "account-status principal/PCR binding mismatch",
        ));
    }
    Ok(())
}

#[salvo::oapi::endpoint(operation_id = "ak.peer.signal.command.relay", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.peer.signal.command.relay.v1"))]
async fn peer_signal_relay(depot: &mut Depot, req: &mut Request) -> JsonResult<SignalRelayOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    if req.headers().contains_key("idempotency-key") {
        return Err(schema_violation(
            "ak.peer.signal.command.relay.v1 forbids Idempotency-Key",
        ));
    }
    validate_peer_request(state, req, true).await?;
    validate_signal_signature_window(req)?;
    let request = parse_json_body::<SignalRelayRequest>(
        req,
        "invalid ak.peer.signal.command.relay.v1 request body",
    )
    .await?;
    request
        .validate()
        .map_err(|error| schema_violation(error.to_string()))?;
    let source_id = source_id_from_request(req)?;
    for envelope in request.signals {
        if let Err(error) =
            super::sync::signal::accept_peer_signal(state, &source_id, &envelope).await
        {
            tracing::debug!(
                %error,
                realm_id = %request.realm_id,
                "peer signal item silently dropped"
            );
        }
    }
    json_ok(SignalRelayOutcome::ACCEPTED)
}

fn validate_signal_signature_window(req: &Request) -> Result<(), AppError> {
    let signature_input =
        soland_http::http_signature::parse_signature_input_header(req).map_err(|error| {
            schema_violation(format!("invalid Signal relay Signature-Input: {error}"))
        })?;
    if signature_input.expires < signature_input.created
        || signature_input.expires - signature_input.created > 5
    {
        return Err(AppError::capability_denied(
            "Signal relay signature validity window must be at most 5 seconds",
        ));
    }
    Ok(())
}

#[salvo::oapi::endpoint(operation_id = "ak.peer.events.read.describe", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.peer.events.read.describe.v1"))]
async fn peer_events_describe(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<arkret_models_discovery::ServiceDescribe> {
    if req.method().as_str() == "QUERY" {
        parse_json_body::<PeerEventsDescribeRequestBody>(
            req,
            "invalid ak.peer.events.read.describe.v1 request body",
        )
        .await?;
    }
    let state = depot.get_typed::<AppState>().expect("state injected");
    let mut description = crate::routing::system::describe::build_server_description(state);
    description.supported_profiles = vec![
        arkret_wire::ProfileId::FEDERATION_MINIMAL_V1.to_owned(),
        arkret_wire::ProfileId::SIGNAL_PEER_RELAY_V1.to_owned(),
    ];
    description.limits.extensions.insert(
        "peer_events".to_owned(),
        serde_json::to_value(PeerEventsDescribeLimits {
            max_batch_item_count: MAX_FEDERATED_EVENTS,
            max_query_limit: MAX_PEER_EVENTS_READ_LIMIT,
            max_resolve: MAX_PEER_EVENTS_RESOLVE,
        })
        .expect("peer limits serialize"),
    );
    description.claimed_profiles = description
        .supported_profiles
        .iter()
        .map(arkret_models_discovery::ClaimedProfileEntry::self_claimed)
        .collect();
    description.validate().map_err(|error| {
        AppError::internal(format!("peer ServiceDescribe validation failed: {error}"))
    })?;
    json_ok(description)
}

#[salvo::oapi::endpoint(operation_id = "ak.peer.events.command.submit", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.peer.events.command.submit.v1"))]
async fn peer_events_submit(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.get_typed::<AppState>().expect("state injected");
    if let Err(error) = validate_peer_request(state, req, true).await {
        render_app_error(res, error);
        return;
    }
    let body_value = match req.parse_json::<Value>().await {
        Ok(body) => body,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "json_invalid",
                "invalid ak.peer.events.command.submit.v1 request body",
            );
            return;
        }
    };
    if let Err(error) =
        serde_json::from_value::<EventsSubmitFederationRequestBody>(body_value.clone())
    {
        render_app_error(
            res,
            schema_violation(format!(
                "invalid ak.peer.events.command.submit.v1 request body: {error}"
            )),
        );
        return;
    }
    super::event_log::submit_federation_events(state, req, body_value, res).await;
}

#[salvo::oapi::endpoint(operation_id = "ak.peer.events.read.scan", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.peer.events.read.scan.v1"))]
async fn peer_events_read_body(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<EventsQueryOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    validate_peer_request(state, req, true).await?;
    let request = parse_json_body::<EventsQueryPostRequestBody>(
        req,
        "invalid ak.peer.events.read.scan.v1 request body",
    )
    .await?;
    let source_id = source_id_from_request(req)?;
    let parts = PeerEventsQueryParts::from_body(request)?;
    peer_events_query_response(state, source_id, parts).await
}

#[salvo::oapi::endpoint(operation_id = "ak.peer.events.read.resolve", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.peer.events.read.resolve.v1"))]
async fn peer_events_resolve(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PeerEventsResolveOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    validate_peer_request(state, req, true).await?;
    let request = parse_json_body::<PeerEventsResolveRequestBody>(
        req,
        "invalid ak.peer.events.read.resolve.v1 request body",
    )
    .await?;
    request
        .validate()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    if request.history_traversal_access.is_some() && request.include_payload == Some(false) {
        return Err(AppError::param_invalid(
            "history traversal requires the complete accepted Event payload",
        ));
    }
    let source_id = source_id_from_request(req)?;
    for digest in &request.event_digests {
        if !is_valid_hash_digest(digest.as_str()) {
            return Err(AppError::param_invalid(format!(
                "invalid event digest: {digest}"
            )));
        }
    }
    let include_payload = request.include_payload.unwrap_or(true);
    let requested_ids = request
        .event_ids
        .iter()
        .map(|event_id| event_id.as_str())
        .collect::<BTreeSet<_>>();
    let requested_digests = request
        .event_digests
        .iter()
        .map(|digest| digest.as_str())
        .collect::<BTreeSet<_>>();
    let source_service_core_id = DidCoreId::new(source_id.clone()).map_err(|error| {
        AppError::param_invalid(format!("source-service-id is not a core_id: {error}"))
    })?;
    let history = state.persistence().governance_history_service();
    if let Some(access) = request.history_traversal_access.clone() {
        let retained = history
            .resolve_peer_retained_events(
                &request.realm_id,
                access,
                &source_service_core_id,
                chrono::Utc::now(),
            )
            .await
            .map_err(|error| {
                AppError::internal(format!("peer history traversal access: {error}"))
            })?;
        let mut events = Vec::new();
        let mut found_ids = BTreeSet::new();
        let mut found_digests = BTreeSet::new();
        for event in retained {
            let digest_suite = arkret::signed_event_digest_claim(&event)
                .and_then(|digest| digest.digest_suite().map_err(Into::into))
                .map_err(|error| AppError::internal(error.to_string()))?;
            let event_digest = arkret_wire::Hash::new(
                event
                    .event_digest_with_digest_suite(digest_suite)
                    .map_err(|error| AppError::internal(error.to_string()))?,
            )
            .map_err(|error| AppError::internal(error.to_string()))?;
            let id_match = requested_ids.contains(event.event_id.as_str());
            let digest_match = requested_digests.contains(event_digest.as_str());
            if !id_match && !digest_match {
                continue;
            }
            found_ids.insert(event.event_id.as_str().to_owned());
            found_digests.insert(event_digest.as_str().to_owned());
            events.push(event);
        }
        events.sort_by(|left, right| left.event_id.as_str().cmp(right.event_id.as_str()));
        let outcome = PeerEventsResolveOutcome {
            events,
            missing_event_ids: request
                .event_ids
                .iter()
                .filter(|event_id| !found_ids.contains(event_id.as_str()))
                .cloned()
                .collect(),
            missing_event_digests: request
                .event_digests
                .iter()
                .filter(|digest| !found_digests.contains(digest.as_str()))
                .cloned()
                .collect(),
        };
        outcome
            .validate_structural()
            .map_err(|error| AppError::internal(error.to_string()))?;
        let response_bytes = arkret_canonical::canonical_json_bytes(&outcome)
            .map_err(|error| AppError::internal(format!("peer resolve response: {error}")))?;
        let budget = request.max_response_bytes.unwrap_or(8 * 1024 * 1024) as usize;
        if response_bytes.len() > budget {
            return Err(AppError::new(
                soland_http::error::ErrorCode::LimitExceeded,
                "peer dependency response exceeds max_response_bytes",
            ));
        }
        return json_ok(outcome);
    }
    let records = state
        .event_queries()
        .canonical_events()
        .await
        .map_err(|error| AppError::internal(format!("peer events resolve: {error}")))?;
    let authz = PeerReadAuthz::build(state, &source_id, &records).await?;
    let mut events = Vec::new();
    let mut found_ids = BTreeSet::new();
    let mut found_digests = BTreeSet::new();
    for record in records {
        if record.realm_id.as_deref() != Some(request.realm_id.as_str()) {
            continue;
        }
        let id_match = requested_ids.contains(record.event_id.as_str());
        let digest_match = requested_digests.contains(record.canonical_digest.as_str());
        if !id_match && !digest_match {
            continue;
        }
        if !authz.record_visible(&record) {
            continue;
        }
        found_ids.insert(record.event_id.clone());
        found_digests.insert(record.canonical_digest.clone());
        let mut event = super::event_log::sdk_event_for_state(state, &record)?;
        if !include_payload {
            event.payload.clear();
        }
        events.push(event);
    }
    events.sort_by(|left, right| left.event_id.as_str().cmp(right.event_id.as_str()));
    let mut missing_event_ids = Vec::new();
    for id in &request.event_ids {
        if !found_ids.contains(id.as_str()) {
            missing_event_ids.push(id.clone());
        }
    }
    let mut missing_event_digests = Vec::new();
    for digest in &request.event_digests {
        if !found_digests.contains(digest.as_str()) {
            missing_event_digests.push(digest.clone());
        }
    }
    let outcome = PeerEventsResolveOutcome {
        events,
        missing_event_ids,
        missing_event_digests,
    };
    outcome
        .validate_structural()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let response_bytes = arkret_canonical::canonical_json_bytes(&outcome)
        .map_err(|error| AppError::internal(format!("peer resolve response: {error}")))?;
    let budget = request.max_response_bytes.unwrap_or(8 * 1024 * 1024) as usize;
    if response_bytes.len() > budget {
        return Err(AppError::new(
            soland_http::error::ErrorCode::LimitExceeded,
            "peer dependency response exceeds max_response_bytes",
        ));
    }
    json_ok(outcome)
}

#[salvo::oapi::endpoint(operation_id = "ak.peer.events.read.frontier", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.peer.events.read.frontier.v1"))]
async fn peer_events_frontier(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<EventsFrontierFederationPeerState> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let has_body = req.method().as_str() == "QUERY";
    validate_peer_request(state, req, has_body).await?;
    let source_id = source_id_from_request(req)?;
    let (realm_id, frontier_actor_id) = if has_body {
        let body = parse_json_body::<PeerEventsFrontierRequestBody>(
            req,
            "invalid ak.peer.events.read.frontier.v1 request body",
        )
        .await?;
        (body.realm_id.into_string(), body.actor_id)
    } else {
        (
            query_param(req, "realm_id")
                .ok_or_else(|| AppError::param_missing("realm_id is required"))?,
            None,
        )
    };
    let realm_id =
        RealmId::new(realm_id).map_err(|_| AppError::param_invalid("invalid realm_id"))?;
    if is_realm_deleted(state, realm_id.as_str()).await {
        return Err(AppError::not_found("not found"));
    }
    let records = state
        .event_queries()
        .canonical_events()
        .await
        .map_err(|error| AppError::internal(format!("peer frontier: {error}")))?;
    let authz = PeerReadAuthz::build(state, &source_id, &records).await?;
    if !authz.frontier_visible_for_realm(realm_id.as_str()) {
        return Err(AppError::not_found("not found"));
    }
    let visible_realm_records = records
        .iter()
        .filter(|record| {
            super::event_log::canonical_realm_id_for_record(record).as_deref()
                == Some(realm_id.as_str())
                && authz.record_visible(record)
        })
        .collect::<Vec<_>>();
    let mut actor_frontier: BTreeMap<String, u64> = BTreeMap::new();
    let mut max_hlc: Option<String> = None;
    for record in &visible_realm_records {
        actor_frontier
            .entry(record.actor_id.clone())
            .and_modify(|seq| *seq = (*seq).max(record.actor_seq))
            .or_insert(record.actor_seq);
        if let Some(hlc) = record.envelope.get("hlc").and_then(Value::as_str) {
            max_hlc = match max_hlc {
                Some(current) if current.as_str() >= hlc => Some(current),
                _ => Some(hlc.to_owned()),
            };
        }
    }
    let mut heads = visible_realm_records
        .iter()
        .filter(|record| {
            actor_frontier
                .get(record.actor_id.as_str())
                .is_some_and(|seq| *seq == record.actor_seq)
        })
        .map(|record| record.event_id.clone())
        .collect::<Vec<_>>();
    heads.sort();
    heads.dedup();
    let typed_heads = heads
        .iter()
        .map(|event_id| {
            EventId::new(event_id.clone())
                .map_err(|_| AppError::internal("stored frontier event_id is invalid"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let typed_actor_frontier = actor_frontier
        .iter()
        .map(|(actor_id, seq)| {
            Ok((
                arkret_identifiers::DidCoreId::new(actor_id.clone())
                    .map_err(|_| AppError::internal("stored frontier actor_id is invalid"))?,
                *seq,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, AppError>>()?;
    let typed_realm_frontier =
        super::frontier::typed_realm_frontier([(realm_id.as_str().to_owned(), heads.clone())]);
    let typed_actor_bounds = super::frontier::typed_actor_upper_bounds(actor_frontier.clone());
    let frontier_root = super::frontier::frontier_root(&typed_realm_frontier, &typed_actor_bounds)
        .map_err(|error| AppError::internal(format!("frontier_root: {error}")))?;
    let projection = state.projections().snapshot();
    let (auth_state_root, policy_frontier_root, membership_frontier_root) =
        if let Some(actor_id) = frontier_actor_id.as_ref() {
            let policy = projection
                .realm_policy_frontier_digest(realm_id.as_str())
                .ok_or_else(|| AppError::internal("policy frontier state root failed"))?;
            let membership = projection
                .realm_membership_frontier_digest(realm_id.as_str(), actor_id.as_str())
                .ok_or_else(|| AppError::not_found("not found"))?;
            let authorization = projection
                .realm_authorization_state_digest(realm_id.as_str(), actor_id.as_str())
                .ok_or_else(|| AppError::internal("authorization state root failed"))?;
            (Some(authorization), Some(policy), Some(membership))
        } else {
            (None, None, None)
        };
    let service_id = DidCoreId::new(state.service_id().clone())
        .map_err(|_| AppError::internal("service_id is invalid"))?;
    let service_did = state.service_resolution_commitment().did.clone();
    let observed_at = now();
    let signature = super::frontier::sign_frontier_root(
        &service_id,
        &service_did,
        Some(&realm_id),
        observed_at,
        &frontier_root,
        auth_state_root.as_ref(),
        policy_frontier_root.as_ref(),
        membership_frontier_root.as_ref(),
        state.notary_signing_key().as_ref(),
    )
    .map_err(|error| AppError::internal(format!("frontier signature: {error}")))?;
    json_ok(EventsFrontierFederationPeerState {
        realm_id,
        head_ids: typed_heads,
        frontier_root,
        auth_state_root,
        policy_frontier_root,
        membership_frontier_root,
        actor_seq_upper_bounds: typed_actor_frontier,
        witness_receipts: Vec::new(),
        observed_at: arkret_canonical::format_timestamp_canonical(observed_at),
        issuer_id: service_id,
        signature: signature
            .as_object()
            .expect("frontier signature must be an object")
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
        max_hlc,
    })
}

#[derive(Serialize)]
struct PeerSealFrontierProofBinding<'a> {
    context: &'static str,
    frontier: &'a RealmSealFrontierView,
    verification_method: &'a arkret_wire::DidUrl,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    created_at: DateTime<Utc>,
}

#[salvo::oapi::endpoint(operation_id = "ak.peer.seals.read.frontier", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.peer.seals.read.frontier.v1"))]
async fn peer_seals_frontier(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PeerSealFrontierState> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    validate_peer_request(state, req, true).await?;
    let source_id = source_id_from_request(req)?;
    let request = parse_json_body::<SealFrontierRequestBody>(
        req,
        "invalid ak.peer.seals.read.frontier.v1 request body",
    )
    .await?;
    if is_realm_deleted(state, request.realm_id.as_str()).await
        || !peer_realm_visibility(state, &source_id, request.realm_id.as_str()).await?
    {
        return Err(AppError::not_found("not found"));
    }
    let frontier =
        super::event_log::endpoints::load_realm_seal_frontier(state, &request.realm_id).await?;
    let created_at = frontier.observation_coordinate.observed_at;
    let verification_method = state
        .service_verification_method("notary-key")
        .map_err(|error| AppError::internal(error.to_string()))?;
    let frontier_bytes = arkret_canonical::canonical_json_bytes(&frontier)
        .map_err(|error| AppError::internal(format!("peer Seal frontier: {error}")))?;
    let payload_digest = arkret_wire::Hash::new(format!("sha256:{}", sha256_hex(&frontier_bytes)))
        .map_err(|error| AppError::internal(error.to_string()))?;
    let binding = PeerSealFrontierProofBinding {
        context: arkret_wire::ProofContextId::PEER_SEAL_FRONTIER_PROOF_V1,
        frontier: &frontier,
        verification_method: &verification_method,
        created_at,
    };
    let binding_bytes = arkret_canonical::canonical_json_bytes(&binding)
        .map_err(|error| AppError::internal(format!("peer Seal frontier proof: {error}")))?;
    let jws = arkret_signatures::jws::sign_jws_ed25519(
        &binding_bytes,
        state.notary_signing_key().as_ref(),
    )
    .map_err(|error| AppError::internal(format!("peer Seal frontier signing failed: {error}")))?;
    let service_proof = arkret_wire::PayloadProof {
        kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
        verification_method,
        payload_digest,
        created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws,
    };
    service_proof
        .validate_production()
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(PeerSealFrontierState {
        frontier,
        service_proof,
    })
}

/// Spec resolution (2026-06-11): `ak.peer.snapshot.read.manifest_head.v1` returns the full
/// signed `ak.schema.snapshot.v1` manifest. soland cannot produce a real
/// Snapshot detached proof yet, and the spec forbids serving a dev-signed
/// stand-in (`signature` / `authority_binding` / `event_set_commitment`
/// MUST NOT be fabricated — service-http-binding.md §6.1, service-surface.md
/// §5.2). The operation is therefore undeclared and the endpoint fails
/// closed with `not_implemented` until a real signing path lands. The
/// dev snapshot bundle remains reachable on the `/_soland/` product face
/// (`org.arkret.soland.sync.snapshot_chunk`).
#[salvo::oapi::endpoint(operation_id = "ak.peer.snapshot.read.manifest_head", tags("events"))]
#[tracing::instrument(skip_all, fields(op = "ak.peer.snapshot.read.manifest_head.v1"))]
async fn peer_snapshot_head(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PeerSnapshotHeadOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    validate_peer_request(state, req, false).await?;
    Err(AppError::new(
        soland_http::error::ErrorCode::NotImplemented,
        "ak.peer.snapshot.read.manifest_head.v1 is not implemented: this deployment cannot \
         produce a signed ak.schema.snapshot.v1 manifest",
    ))
}

#[derive(Debug)]
struct PeerEventsQueryParts {
    realms: Vec<String>,
    actors: Vec<String>,
    after: Option<String>,
    before: Option<String>,
    order: String,
    limit: usize,
    kind_filter: Option<String>,
}

impl PeerEventsQueryParts {
    fn from_body(body: EventsQueryPostRequestBody) -> Result<Self, AppError> {
        let filters = body
            .filters
            .as_ref()
            .and_then(|filters| serde_json::to_value(filters).ok());
        let kind_filter = parse_kind_filter(filters.as_ref())?;
        let parts = Self {
            realms: body
                .realm_ids
                .into_iter()
                .map(|realm| realm.into_string())
                .collect(),
            actors: body
                .actor_ids
                .into_iter()
                .map(|actor| actor.into_string())
                .collect(),
            after: body.after.map(|cursor| cursor.into_string()),
            before: body.before.map(|cursor| cursor.into_string()),
            order: body.order.unwrap_or_else(|| "default".to_owned()),
            limit: body
                .limit
                .map(|limit| limit as usize)
                .unwrap_or(MAX_PEER_EVENTS_READ_LIMIT)
                .clamp(1, MAX_PEER_EVENTS_READ_LIMIT),
            kind_filter,
        };
        parts.validate()?;
        Ok(parts)
    }

    fn validate(&self) -> Result<(), AppError> {
        if self.realms.is_empty() && self.actors.is_empty() {
            return Err(AppError::param_missing(
                "ak.peer.events.read.scan.v1 requires at least one of realms[] / actors[]",
            ));
        }
        if self.after.is_some() && self.before.is_some() {
            return Err(AppError::param_invalid(
                "specify either 'after' or 'before', not both",
            ));
        }
        if !matches!(self.order.as_str(), "default" | "ascending" | "descending") {
            return Err(AppError::param_invalid(
                "order must be default, ascending, or descending",
            ));
        }
        for realm in &self.realms {
            RealmId::new(realm.clone())
                .map_err(|_| AppError::param_invalid(format!("invalid realm: {realm}")))?;
        }
        for actor in &self.actors {
            if validate_did(actor).is_err() {
                return Err(AppError::param_invalid(format!("invalid actor: {actor}")));
            }
        }
        if let Some(kind) = &self.kind_filter
            && (!kind.starts_with("ak.") || kind.contains(' '))
        {
            return Err(AppError::param_invalid(format!(
                "invalid event kind: {kind}"
            )));
        }
        Ok(())
    }

    fn backward(&self) -> bool {
        if self.before.is_some() {
            true
        } else if self.after.is_some() {
            false
        } else {
            self.order != "ascending"
        }
    }

    fn active_cursor(&self) -> Option<&str> {
        self.before.as_deref().or(self.after.as_deref())
    }

    fn filters_for_digest(&self) -> Value {
        match self.kind_filter.as_deref() {
            Some(kind) => json!({ "kind": kind }),
            None => json!({}),
        }
    }
}

#[derive(Clone, Debug)]
struct PeerReadAuthz {
    source_id: String,
    realm_meta: BTreeMap<String, RealmMetaRecord>,
    realm_members: BTreeMap<String, BTreeMap<String, PeerMembership>>,
    pending_realm_invites: BTreeMap<(String, String), PendingPeerInvite>,
    circles: BTreeMap<String, PeerCircleState>,
    circle_members: BTreeMap<String, BTreeMap<String, PeerMembership>>,
}

#[derive(Clone, Debug)]
struct PeerMembership {
    joined_at: DateTime<Utc>,
    invited_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug)]
struct PendingPeerInvite {
    invitee_id: String,
    invited_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
struct PeerCircleState {
    realm_id: String,
    history_access: String,
    active: bool,
}

impl PeerReadAuthz {
    async fn build(
        state: &AppState,
        source_id: &str,
        records: &[AcceptedEvent],
    ) -> Result<Self, AppError> {
        let realm_meta = state
            .realms()
            .realm_metadata_list()
            .await
            .map_err(|error| AppError::internal(format!("peer realm metadata: {error}")))?
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        let circles = state
            .projections()
            .snapshot()
            .circles
            .iter()
            .map(|(circle_id, circle)| {
                (
                    circle_id.clone(),
                    PeerCircleState {
                        realm_id: circle.realm_id.clone(),
                        history_access: circle.history_access.clone(),
                        active: circle.state.as_str() == "active",
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mut authz = Self {
            source_id: source_id.to_owned(),
            realm_meta,
            realm_members: BTreeMap::new(),
            pending_realm_invites: BTreeMap::new(),
            circles,
            circle_members: BTreeMap::new(),
        };
        let mut ordered = records.iter().collect::<Vec<_>>();
        ordered.sort_by(|left, right| {
            left.received_at
                .cmp(&right.received_at)
                .then_with(|| left.event_id.cmp(&right.event_id))
        });
        for record in ordered {
            authz.apply_record(record);
        }
        Ok(authz)
    }

    fn apply_record(&mut self, record: &AcceptedEvent) {
        self.apply_invite_record(record);
        self.apply_member_record(record);
        self.apply_circle_member_record(record);
    }

    fn apply_invite_record(&mut self, record: &AcceptedEvent) {
        let Some(realm_id) = super::event_log::canonical_realm_id_for_record(record) else {
            return;
        };
        let Some(payload) = record_payload(record) else {
            return;
        };
        match arkret_wire::EventKind::from_wire(&record.kind) {
            arkret_wire::EventKind::InviteCreate => {
                let Some(invite_id) = payload.get("invite_id").and_then(Value::as_str) else {
                    return;
                };
                let Some(invitee_id) = payload.get("invitee_id").and_then(Value::as_str) else {
                    return;
                };
                let source_matches = payload
                    .get("invite_delivery_target")
                    .and_then(Value::as_object)
                    .and_then(|target| target.get("recipient_id"))
                    .and_then(Value::as_str)
                    .is_some_and(|service_id| service_id == self.source_id);
                if source_matches {
                    self.pending_realm_invites.insert(
                        (realm_id, invite_id.to_owned()),
                        PendingPeerInvite {
                            invitee_id: invitee_id.to_owned(),
                            invited_at: record_event_time(record),
                        },
                    );
                }
            }
            arkret_wire::EventKind::InviteAccept => {
                let Some(invite_id) = payload
                    .get("invite_id")
                    .or_else(|| payload.get("invite_ref"))
                    .and_then(Value::as_str)
                else {
                    return;
                };
                let Some(invite) = self
                    .pending_realm_invites
                    .remove(&(realm_id.clone(), invite_id.to_owned()))
                else {
                    return;
                };
                if record.actor_id != invite.invitee_id {
                    return;
                }
                self.realm_members.entry(realm_id).or_default().insert(
                    invite.invitee_id,
                    PeerMembership {
                        joined_at: record_event_time(record),
                        invited_at: Some(invite.invited_at),
                    },
                );
            }
            _ => {}
        }
    }

    fn record_visible(&self, record: &AcceptedEvent) -> bool {
        let Some(realm_id) = super::event_log::canonical_realm_id_for_record(record) else {
            return false;
        };
        let Some(meta) = self.realm_meta.get(&realm_id) else {
            return false;
        };
        if meta.deleted {
            return false;
        }
        if !self.source_has_realm_scope(&realm_id) {
            return false;
        }
        let event_time = record_event_time(record);
        let needs_plaintext = record_requires_private_plaintext_visibility(record, meta);
        if needs_plaintext && !self.source_can_receive_plaintext(&realm_id) {
            return false;
        }
        if let Some(circle_id) = record_scope_circle_id(record) {
            return self.circle_record_visible(&realm_id, &circle_id, event_time);
        }
        self.realm_record_visible(&realm_id, meta, event_time, needs_plaintext)
    }

    fn frontier_visible_for_realm(&self, realm_id: &str) -> bool {
        self.realm_meta
            .get(realm_id)
            .is_some_and(|meta| !meta.deleted)
            && self
                .realm_members
                .get(realm_id)
                .is_some_and(|members| !members.is_empty())
    }

    fn source_has_realm_scope(&self, realm_id: &str) -> bool {
        self.realm_members
            .get(realm_id)
            .is_some_and(|members| !members.is_empty())
    }

    fn source_scoped_realms(&self) -> Vec<String> {
        let realms = self
            .realm_members
            .keys()
            .filter(|realm_id| {
                self.realm_meta
                    .get(realm_id.as_str())
                    .is_some_and(|meta| !meta.deleted)
            })
            .cloned()
            .collect::<BTreeSet<_>>();
        realms
            .iter()
            .filter(|realm_id| self.source_has_realm_scope(realm_id.as_str()))
            .cloned()
            .collect()
    }

    fn realm_record_visible(
        &self,
        realm_id: &str,
        meta: &RealmMetaRecord,
        event_time: DateTime<Utc>,
        _needs_plaintext: bool,
    ) -> bool {
        self.realm_members.get(realm_id).is_some_and(|members| {
            members.values().any(|member| {
                history_access_allows(meta.history_access.as_str(), member, event_time)
            })
        })
    }

    fn circle_record_visible(
        &self,
        realm_id: &str,
        circle_id: &str,
        event_time: DateTime<Utc>,
    ) -> bool {
        let Some(circle) = self.circles.get(circle_id) else {
            return false;
        };
        if !circle.active || circle.realm_id != realm_id {
            return false;
        }
        let Some(realm_members) = self.realm_members.get(realm_id) else {
            return false;
        };
        let Some(circle_members) = self.circle_members.get(circle_id) else {
            return false;
        };
        realm_members.iter().any(|(actor, realm_member)| {
            circle_members.get(actor).is_some_and(|circle_member| {
                history_access_allows(circle.history_access.as_str(), circle_member, event_time)
                    && history_access_allows("since_join", realm_member, event_time)
            })
        })
    }

    fn source_can_receive_plaintext(&self, realm_id: &str) -> bool {
        let Some(meta) = self.realm_meta.get(realm_id) else {
            return false;
        };
        if !meta
            .plaintext_visible_services
            .contains(self.source_id.as_str())
        {
            return false;
        }
        self.realm_members
            .get(realm_id)
            .is_some_and(|members| !members.is_empty())
    }

    fn apply_member_record(&mut self, record: &AcceptedEvent) {
        if record.kind != arkret_wire::EventKind::MemberState.as_str() {
            return;
        }
        let Some(realm_id) = super::event_log::canonical_realm_id_for_record(record) else {
            return;
        };
        let Some(payload) = record_payload(record) else {
            return;
        };
        let Some(actor) = payload
            .get("actor_id")
            .and_then(Value::as_str)
            .or_else(|| payload.get("actor").and_then(Value::as_str))
        else {
            return;
        };
        let membership = payload
            .get("membership")
            .and_then(Value::as_str)
            .or_else(|| payload.get("state").and_then(Value::as_str))
            .unwrap_or_default();
        match membership {
            "join" | "active" => {
                let Some(binding) = payload.get("delivery_binding").and_then(Value::as_object)
                else {
                    self.remove_realm_member(&realm_id, actor);
                    return;
                };
                let source_matches = binding
                    .get("recipient_id")
                    .and_then(Value::as_str)
                    .is_some_and(|did| did == self.source_id);
                let routable = payload
                    .get("delivery_status")
                    .and_then(Value::as_str)
                    .is_none_or(|status| status == "routable");
                if !source_matches || !routable || !binding_expiry_allows(binding.get("expires_at"))
                {
                    self.remove_realm_member(&realm_id, actor);
                    return;
                }
                let previous = self
                    .realm_members
                    .get(&realm_id)
                    .and_then(|members| members.get(actor));
                let membership = PeerMembership {
                    joined_at: previous
                        .map(|member| member.joined_at)
                        .unwrap_or_else(|| record_event_time(record)),
                    invited_at: previous.and_then(|member| member.invited_at),
                };
                self.realm_members
                    .entry(realm_id)
                    .or_default()
                    .insert(actor.to_owned(), membership);
            }
            "invite" | "invited" => {
                if let Some(member) = self
                    .realm_members
                    .entry(realm_id)
                    .or_default()
                    .get_mut(actor)
                {
                    member
                        .invited_at
                        .get_or_insert_with(|| record_event_time(record));
                }
            }
            "leave" | "ban" | "removed" | "banned" | "left" => {
                self.remove_realm_member(&realm_id, actor);
            }
            _ => {}
        }
    }

    fn remove_realm_member(&mut self, realm_id: &str, actor: &str) {
        if let Some(members) = self.realm_members.get_mut(realm_id) {
            members.remove(actor);
            if members.is_empty() {
                self.realm_members.remove(realm_id);
            }
        }
    }

    fn apply_circle_member_record(&mut self, record: &AcceptedEvent) {
        if record.kind != arkret_wire::EventKind::CircleMemberState.as_str() {
            return;
        }
        let Some(payload) = record_payload(record) else {
            return;
        };
        let Some(circle_id) = payload.get("circle_id").and_then(Value::as_str) else {
            return;
        };
        let Some(actor) = payload
            .get("actor")
            .and_then(Value::as_str)
            .or_else(|| payload.get("actor_id").and_then(Value::as_str))
        else {
            return;
        };
        let state = payload
            .get("state")
            .and_then(Value::as_str)
            .or_else(|| payload.get("membership").and_then(Value::as_str))
            .unwrap_or_default();
        match state {
            "join" | "active" => {
                let previous = self
                    .circle_members
                    .get(circle_id)
                    .and_then(|members| members.get(actor));
                let membership = PeerMembership {
                    joined_at: previous
                        .map(|member| member.joined_at)
                        .unwrap_or_else(|| record_event_time(record)),
                    invited_at: previous.and_then(|member| member.invited_at),
                };
                self.circle_members
                    .entry(circle_id.to_owned())
                    .or_default()
                    .insert(actor.to_owned(), membership);
            }
            "invite" | "invited" => {
                if let Some(member) = self
                    .circle_members
                    .entry(circle_id.to_owned())
                    .or_default()
                    .get_mut(actor)
                {
                    member
                        .invited_at
                        .get_or_insert_with(|| record_event_time(record));
                }
            }
            "leave" | "ban" | "removed" | "banned" | "left" => {
                if let Some(members) = self.circle_members.get_mut(circle_id) {
                    members.remove(actor);
                    if members.is_empty() {
                        self.circle_members.remove(circle_id);
                    }
                }
            }
            _ => {}
        }
    }
}

fn history_access_allows(
    history_access: &str,
    member: &PeerMembership,
    event_time: DateTime<Utc>,
) -> bool {
    match history_access {
        "all_history_for_current_members" => true,
        "since_join" => event_time >= member.joined_at,
        _ => false,
    }
}

fn record_requires_private_plaintext_visibility(
    record: &AcceptedEvent,
    meta: &RealmMetaRecord,
) -> bool {
    let _ = meta;
    let Some(payload) = record_payload(record) else {
        return true;
    };
    !(payload.get("encrypted_content").is_some() || payload.get("encrypted_payload").is_some())
}

fn record_scope_circle_id(record: &AcceptedEvent) -> Option<String> {
    let object = record.envelope.as_object()?;
    let scope = object.get("scope_ref")?.as_object()?;
    if scope.get("kind").and_then(Value::as_str) != Some("circle") {
        return None;
    }
    scope
        .get("circle_id")
        .and_then(Value::as_str)
        .filter(|scope| scope.starts_with("ak:circle:"))
        .map(ToOwned::to_owned)
}

fn record_payload(record: &AcceptedEvent) -> Option<&serde_json::Map<String, Value>> {
    record.envelope.get("payload").and_then(Value::as_object)
}

fn record_event_time(record: &AcceptedEvent) -> DateTime<Utc> {
    record
        .envelope
        .get("created_at")
        .and_then(Value::as_str)
        .and_then(parse_rfc3339)
        .unwrap_or(record.received_at)
}

fn parse_rfc3339(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

fn binding_expiry_allows(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .and_then(parse_rfc3339)
        .is_none_or(|expires_at| expires_at > Utc::now())
}

async fn peer_events_query_response(
    state: &AppState,
    source_id: String,
    parts: PeerEventsQueryParts,
) -> JsonResult<EventsQueryOutcome> {
    let realms_set = parts
        .realms
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let actors_set = parts
        .actors
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let filter_digest = peer_events_query_scope_digest(&source_id, &parts);
    let cursor_event_id =
        peer_events_query_cursor_event_id(state, parts.active_cursor(), &filter_digest).await?;
    let authz_records = state
        .event_queries()
        .peer_authz_state_records()
        .await
        .map_err(|error| AppError::internal(format!("peer events query: {error}")))?;
    let authz = PeerReadAuthz::build(state, &source_id, &authz_records).await?;
    let backward = parts.backward();
    let query_realms = if parts.realms.is_empty() {
        authz.source_scoped_realms()
    } else {
        parts.realms.clone()
    };
    if query_realms.is_empty() {
        return json_ok(EventsQueryOutcome {
            events: Vec::new(),
            snapshot_bootstrap: None,
            next_cursor: None,
            prev_cursor: None,
            has_more: false,
            range_completeness: None,
        });
    }
    let candidate_limit = peer_events_candidate_limit(parts.limit);
    let mut scan_cursor_event_id = cursor_event_id;
    let mut visible = Vec::new();
    loop {
        let candidates = state
            .event_queries()
            .peer_events_query_page(&PeerEventsPageQuery {
                realms: query_realms.clone(),
                actors: parts.actors.clone(),
                kind_filter: parts.kind_filter.clone(),
                cursor_event_id: scan_cursor_event_id.clone(),
                backward,
                limit: candidate_limit,
            })
            .await
            .map_err(|error| AppError::internal(format!("peer events query page: {error}")))?;
        let candidate_count = candidates.len();
        let next_scan_cursor = candidates.last().map(|record| record.event_id.clone());
        for record in candidates {
            if peer_record_matches(
                &record,
                &realms_set,
                &actors_set,
                parts.kind_filter.as_deref(),
            ) && authz.record_visible(&record)
            {
                visible.push(record);
                if visible.len() > parts.limit {
                    break;
                }
            }
        }
        if visible.len() > parts.limit || candidate_count < candidate_limit {
            break;
        }
        let Some(next_scan_cursor) = next_scan_cursor else {
            break;
        };
        scan_cursor_event_id = Some(next_scan_cursor);
    }
    let has_more = visible.len() > parts.limit;
    if has_more {
        visible.truncate(parts.limit);
    }
    let page_cursor_event_id = has_more
        .then(|| visible.last().map(|record| record.event_id.clone()))
        .flatten();
    let page_cursor = match page_cursor_event_id {
        Some(event_id) => Some(
            super::sync::sync_token_for_events_query(state, None, &filter_digest, &event_id).await,
        ),
        None => None,
    };
    let (next_cursor, prev_cursor) = if backward {
        (None, page_cursor)
    } else {
        (page_cursor, None)
    };
    let events = visible
        .iter()
        .map(|record| super::event_log::sdk_event_for_state(state, record))
        .map(|event| event.map(Into::into))
        .collect::<Result<Vec<_>, _>>()?;
    json_ok(EventsQueryOutcome {
        events,
        snapshot_bootstrap: None,
        next_cursor,
        prev_cursor,
        has_more,
        range_completeness: None,
    })
}

fn peer_events_candidate_limit(page_limit: usize) -> usize {
    page_limit
        .saturating_mul(4)
        .clamp(MAX_PEER_EVENTS_READ_LIMIT, MAX_PEER_EVENTS_READ_LIMIT * 5)
}

fn peer_events_query_scope_digest(source_id: &str, parts: &PeerEventsQueryParts) -> String {
    let realms = parts
        .realms
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let actors = parts
        .actors
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let binding = json!({
        "operation_id": arkret_wire::ServiceOperationId::PEER_EVENTS_READ_SCAN_V1,
        "source_id": source_id,
        "realms": realms,
        "actors": actors,
        "filters": parts.filters_for_digest(),
        "order": parts.order.as_str(),
    });
    super::sync::sync_filter_digest(Some(&binding))
}

async fn peer_events_query_cursor_event_id(
    state: &AppState,
    cursor: Option<&str>,
    filter_digest: &str,
) -> Result<Option<String>, AppError> {
    let Some(cursor) = cursor else {
        return Ok(None);
    };
    super::sync::parse_and_validate_events_query_cursor(
        cursor,
        state,
        None,
        filter_digest,
        Utc::now().timestamp_millis(),
    )
    .await
    .map(|cursor| Some(cursor.event_id))
    .map_err(peer_events_query_cursor_error)
}

fn peer_events_query_cursor_error(error: super::sync::SyncCursorError) -> AppError {
    match error {
        super::sync::SyncCursorError::Expired => AppError::new(
            soland_http::error::ErrorCode::CursorExpired,
            "cursor has expired",
        ),
        // encoding.md §8.3 closed set: syntax/schema failures pin the top-level
        // `param_invalid` code with reason `invalid_cursor`.
        super::sync::SyncCursorError::Invalid(message) => AppError::param_invalid(message)
            .with_reason_code(arkret_wire::ReasonCode::INVALID_CURSOR),
        super::sync::SyncCursorError::Mismatch(message)
        | super::sync::SyncCursorError::Integrity(message) => AppError::new(
            soland_http::error::ErrorCode::CursorIntegrityInvalid,
            message,
        ),
        super::sync::SyncCursorError::Revoked => AppError::new(
            soland_http::error::ErrorCode::CursorRevoked,
            "cursor authority has been revoked",
        ),
    }
}

fn peer_record_matches(
    record: &AcceptedEvent,
    realms: &BTreeSet<&str>,
    actors: &BTreeSet<&str>,
    kind_filter: Option<&str>,
) -> bool {
    if let Some(kind) = kind_filter
        && record.kind != kind
    {
        return false;
    }
    let realm_match = realms.is_empty()
        || super::event_log::canonical_realm_id_for_record(record)
            .as_deref()
            .is_some_and(|realm_id| realms.contains(realm_id));
    let actor_match = actors.is_empty() || actors.contains(record.actor_id.as_str());
    realm_match && actor_match
}

fn parse_kind_filter(filters: Option<&Value>) -> Result<Option<String>, AppError> {
    let Some(filters) = filters else {
        return Ok(None);
    };
    let Some(object) = filters.as_object() else {
        return Err(schema_violation("filters must be an object"));
    };
    let unsupported = object
        .keys()
        .filter(|key| key.as_str() != "kind")
        .cloned()
        .collect::<Vec<_>>();
    if !unsupported.is_empty() {
        return Err(AppError::unsupported_feature(format!(
            "unsupported peer events filter keys: {}",
            unsupported.join(", ")
        )));
    }
    Ok(object
        .get("kind")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned))
}

async fn parse_json_body<T>(req: &mut Request, message: &'static str) -> Result<T, AppError>
where
    T: serde::de::DeserializeOwned,
{
    req.parse_json::<T>()
        .await
        .map_err(|_| AppError::json_invalid(message))
}

pub(in crate::routing) async fn validate_peer_request(
    state: &AppState,
    req: &mut Request,
    has_body: bool,
) -> Result<(), AppError> {
    let expected_destination = state.config().trust_domain.clone();
    if has_body {
        let trust_headers =
            crate::routing::federation::federation::FederationTrustHeaders::from_salvo_request(req)
                .map_err(|violation| {
                    schema_violation(violation.message()).with_wire_code(violation.error_code())
                })?;
        trust_headers
            .verify_destination(&expected_destination)
            .map_err(|_| {
                cross_domain_replay("Destination-Trust-Domain header does not match this service")
            })?;
    } else {
        if req.headers().contains_key("content-digest") {
            return Err(schema_violation(
                "GET peer read requests must not carry body digest headers",
            ));
        }
        if let Some(signature_input) = req
            .headers()
            .get("signature-input")
            .and_then(|value| value.to_str().ok())
        {
            let signature_input = signature_input.to_ascii_lowercase();
            if signature_input.contains("\"content-digest\"") {
                return Err(schema_violation(
                    "GET peer read Signature-Input must not bind body digest components",
                ));
            }
        }
        let destination_trust_domain = required_header(req, "destination-trust-domain")?;
        let destination_trust_domain =
            arkret_identifiers::TrustDomainId::new(destination_trust_domain)
                .map_err(|_| schema_violation("destination-trust-domain must be a trust domain"))?;
        if destination_trust_domain != expected_destination {
            return Err(cross_domain_replay(
                "Destination-Trust-Domain header does not match this service",
            ));
        }
        let source_trust_domain = required_header(req, "source-trust-domain")?;
        arkret_identifiers::TrustDomainId::new(source_trust_domain)
            .map_err(|_| schema_violation("source-trust-domain must be a trust domain"))?;
    }
    let source_id = required_header(req, HEADER_SOURCE_SERVICE_ID)?;
    if validate_did(&source_id).is_err() && arkret_wire::DidCoreId::new(source_id.clone()).is_err()
    {
        return Err(schema_violation(
            "source-service-id must be a service core_id",
        ));
    }
    let destination_id = required_header(req, HEADER_DESTINATION_SERVICE_ID)?;
    if validate_did(&destination_id).is_err()
        && arkret_wire::DidCoreId::new(destination_id.clone()).is_err()
    {
        return Err(schema_violation(
            "destination-service-id must be a service core_id",
        ));
    }
    let local_core =
        arkret_wire::project_did_to_core_id(&state.service_resolution_commitment().did)
            .map(|core| core.into_string())
            .map_err(|_| AppError::internal("local service did cannot be projected"))?;
    if destination_id != *state.service_id() && destination_id != local_core {
        return Err(cross_domain_replay(
            "destination-service-id header does not match this service",
        ));
    }
    // federation.md §3.2/§6: all `/_arkret/peer/*` requests MUST be authenticated
    // with an RFC 9421 HTTP Message Signature verified against the sender's
    // service DID key, and the local peer deny policy MUST be enforced inbound.
    // The bare trust-header checks above are necessary but not sufficient; the
    // signature verification (which also re-binds POST body digests and runs
    // the deny policy) is the authoritative gate.
    crate::routing::federation::federation::verify_inbound_peer_http_signature(
        state, req, has_body,
    )
    .await?;
    Ok(())
}

/// Realm-scoped route mirrors reuse the canonical peer policy and additionally
/// require both requester_id scope and an effective, requester_id-visible reference
/// to the target service. The caller deliberately receives only a boolean so
/// unknown, invisible and not-held targets remain indistinguishable.
pub(in crate::routing) async fn peer_route_visibility(
    state: &AppState,
    source_id: &str,
    realm_id: &str,
    target_id: &str,
) -> Result<bool, AppError> {
    let records = state
        .event_queries()
        .canonical_events()
        .await
        .map_err(|error| AppError::internal(format!("peer route visibility: {error}")))?;
    let authz = PeerReadAuthz::build(state, source_id, &records).await?;
    if !authz.frontier_visible_for_realm(realm_id) {
        return Ok(false);
    }
    Ok(records.iter().any(|record| {
        super::event_log::canonical_realm_id_for_record(record).as_deref() == Some(realm_id)
            && authz.record_visible(record)
            && json_contains_string(&record.envelope, target_id)
    }))
}

pub(in crate::routing) async fn peer_realm_visibility(
    state: &AppState,
    source_id: &str,
    realm_id: &str,
) -> Result<bool, AppError> {
    let records = state
        .event_queries()
        .canonical_events()
        .await
        .map_err(|error| AppError::internal(format!("peer Realm visibility: {error}")))?;
    let authz = PeerReadAuthz::build(state, source_id, &records).await?;
    Ok(authz.frontier_visible_for_realm(realm_id))
}

/// Apply the same accepted-Event history and current membership policy used by
/// peer Event reads to one exact record. This keeps reference-based endpoints
/// from turning an otherwise invisible Event into an object-disclosure oracle.
pub(in crate::routing) async fn peer_event_visibility(
    state: &AppState,
    source_id: &str,
    record: &AcceptedEvent,
) -> Result<bool, AppError> {
    let records = state
        .event_queries()
        .canonical_events()
        .await
        .map_err(|error| AppError::internal(format!("peer Event visibility: {error}")))?;
    let authz = PeerReadAuthz::build(state, source_id, &records).await?;
    Ok(authz.record_visible(record))
}

/// Authorize a near-current peer query for the exact MLS security scope.
/// Sidecar and genesis scopes are deliberately not exposed through the
/// federation surface, matching the self governance-proof visibility rules.
pub(in crate::routing) async fn peer_mls_scope_visibility(
    state: &AppState,
    source_id: &str,
    scope: &arkret_wire::ScopeRef,
) -> Result<bool, AppError> {
    let records = state
        .event_queries()
        .canonical_events()
        .await
        .map_err(|error| AppError::internal(format!("peer MLS scope visibility: {error}")))?;
    let authz = PeerReadAuthz::build(state, source_id, &records).await?;
    Ok(match scope {
        arkret_wire::ScopeRef::Realm { realm_id } => {
            authz.frontier_visible_for_realm(realm_id.as_str())
        }
        arkret_wire::ScopeRef::Circle {
            realm_id,
            circle_id,
        } => {
            authz.frontier_visible_for_realm(realm_id.as_str())
                && authz
                    .circles
                    .get(circle_id.as_str())
                    .is_some_and(|circle| circle.active && circle.realm_id == realm_id.as_str())
                && authz
                    .circle_members
                    .get(circle_id.as_str())
                    .is_some_and(|circle_members| {
                        authz
                            .realm_members
                            .get(realm_id.as_str())
                            .is_some_and(|realm_members| {
                                circle_members
                                    .keys()
                                    .any(|actor| realm_members.contains_key(actor))
                            })
                    })
        }
        _ => false,
    })
}

fn json_contains_string(value: &Value, expected: &str) -> bool {
    match value {
        Value::String(value) => value == expected,
        Value::Array(values) => values
            .iter()
            .any(|value| json_contains_string(value, expected)),
        Value::Object(values) => values
            .values()
            .any(|value| json_contains_string(value, expected)),
        _ => false,
    }
}

pub(in crate::routing) fn source_id_from_request(req: &Request) -> Result<String, AppError> {
    required_header(req, HEADER_SOURCE_SERVICE_ID)
}

fn required_header(req: &Request, name: &'static str) -> Result<String, AppError> {
    req.headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| schema_violation(format!("required federation header {name} missing")))
}

pub(in crate::routing) fn schema_violation(message: impl Into<String>) -> AppError {
    AppError::param_invalid(message)
        .with_status(StatusCode::BAD_REQUEST)
        .with_wire_code("schema_violation")
}

pub(in crate::routing) fn cross_domain_replay(message: impl Into<String>) -> AppError {
    AppError::conflict(message)
        .with_status(StatusCode::CONFLICT)
        .with_wire_code("cross_domain_replay_rejected")
}

fn render_app_error(res: &mut Response, error: AppError) {
    render_error(res, error.http_status(), error.wire_code(), &error.message);
}
