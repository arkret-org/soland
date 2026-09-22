//! Durable Station-to-public-Gateway active registration handoff.

use std::time::Duration;

use arkret_http_client::{Client, HttpMessageSigner};
use arkret_models_integration::{
    PushRegisterDeviceOutcome, PushRegisterDeviceRequestBody, PushRegistrationHandoffRequestBody,
    PushRegistrationId, PushRegistrationRecord,
};
use arkret_wire::{AccountId, ServiceKind, WebOrigin};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use soland_http::error::{AppError, ErrorCode};
use soland_services::push_handoff::{
    ActivePushRegistrationPlan, active_push_registration_client_input_digest,
    plan_active_push_registration,
};
use soland_storage::{
    DeviceRevocationGateSelector, PushRegistrationHandoffIntentRecord,
    PushRegistrationHandoffIntentStatus, PushRegistrationHandoffIntentWrite,
    PushRegistrationHandoffRouteLocator,
};

use crate::push_gateway_registry::TrustedPushGateway;
use crate::state::AppState;

const GATEWAY_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) struct PublicPushRegistration<'a> {
    pub account_id: AccountId,
    pub authorization: &'a DeviceRevocationGateSelector,
    pub body: PushRegisterDeviceRequestBody,
    pub push_route_id: String,
    pub push_target_id: arkret_identifiers::PushTargetId,
    pub prepared_at: DateTime<Utc>,
}

pub(super) async fn register(
    state: &AppState,
    input: PublicPushRegistration<'_>,
) -> Result<PushRegisterDeviceOutcome, AppError> {
    let origin = canonical_gateway_origin(&input.body.push_gateway_url)?;
    let (gateway, route) = resolve_trusted_gateway(state, &origin).await?;
    let source_station_id = state.service_core_id();
    let local_route = PushRegistrationHandoffRouteLocator {
        account_id: input.account_id.clone(),
        device_id: input.body.device_id.clone(),
        push_route_id: input.push_route_id.clone(),
        destination_gateway_id: gateway.service_id().clone(),
    };
    let client_input_digest = active_push_registration_client_input_digest(
        &input.account_id,
        &input.body,
        &input.push_route_id,
        &origin,
        gateway.service_id(),
        &input.push_target_id,
    )
    .map_err(service_storage_error)?;
    let existing = state
        .persistence()
        .push_registration_handoff_for_local_route(&source_station_id, &local_route)
        .await
        .map_err(service_storage_error)?;

    let intent = match plan_active_push_registration(existing, &client_input_digest)
        .map_err(service_storage_error)?
    {
        ActivePushRegistrationPlan::ReturnVerified(record) => return outcome_from_record(&record),
        ActivePushRegistrationPlan::ReplayPending(record) => record,
        ActivePushRegistrationPlan::Create { predecessor } => {
            let request = PushRegistrationHandoffRequestBody::Active {
                registration_id: random_registration_id()?,
                push_target_id: input.push_target_id,
                device_id: input.body.device_id.clone(),
                push_key: input.body.push_key.clone(),
                platform: input.body.platform.clone(),
                app_id: input.body.app_id.clone(),
                visible_notification_opt_in: input.body.visible_notification_opt_in,
                expires_at: None,
                supersedes_registration_id: predecessor,
            };
            let write = state
                .persistence()
                .ensure_push_registration_handoff_intent(
                    &source_station_id,
                    &local_route,
                    &client_input_digest,
                    &request,
                    input.prepared_at,
                )
                .await
                .map_err(service_storage_error)?;
            match write {
                PushRegistrationHandoffIntentWrite::Created(record)
                | PushRegistrationHandoffIntentWrite::ExactReplay(record) => record,
                PushRegistrationHandoffIntentWrite::AdvancedToRevoked(_) => {
                    return Err(AppError::internal(
                        "active Push Gateway registration advanced to revoked unexpectedly",
                    ));
                }
            }
        }
    };

    if intent.status == PushRegistrationHandoffIntentStatus::ReceiptVerified {
        return outcome_from_record(&intent);
    }
    let request = intent.request().map_err(persistence_error)?;
    let (_, assertion_method) = state
        .current_service_receipt_binding()
        .await
        .map_err(|error| handoff_unavailable("source signer is not current", error))?;
    let (_, http) = crate::security::validate_http_url_for_egress_with_pinned_client(
        route.base_url(),
        "public Push Gateway registration handoff",
        state.config().development_mode,
        GATEWAY_REQUEST_TIMEOUT,
    )
    .map_err(|error| handoff_unavailable("Gateway egress denied", error))?;
    let base_url = reqwest::Url::parse(route.base_url())
        .map_err(|error| handoff_unavailable("verified Gateway route is invalid", error))?;
    let client = Client::builder(base_url)
        .http_client(http)
        .http_message_signer(HttpMessageSigner::new(
            assertion_method.as_str(),
            state.notary_signing_key().as_ref().clone(),
        ))
        .build()
        .map_err(|error| handoff_unavailable("Gateway client setup failed", error))?;
    let outcome = client
        .push_apply_registration(&request, &source_station_id, gateway.service_id())
        .await
        .map_err(|error| handoff_unavailable("Gateway request failed", error))?;
    if outcome.receipt.proof.verification_method != *gateway.receipt_verification_method() {
        return Err(handoff_unavailable(
            "Gateway receipt used an unapproved verification method",
            "receipt method mismatch",
        ));
    }
    arkret::verify_push_registration_installation_receipt(
        &outcome.receipt,
        &request,
        &source_station_id,
        gateway.service_id(),
        gateway.receipt_verifying_key(),
    )
    .map_err(|error| handoff_unavailable("Gateway receipt verification failed", error))?;

    let registration = local_registration(
        &intent,
        &request,
        &input.account_id,
        &input.push_route_id,
        &origin,
    )?;
    let committed = state
        .persistence()
        .commit_verified_push_registration_handoff(
            &source_station_id,
            &local_route,
            &intent.registration_id,
            &intent.request_digest,
            &outcome.receipt,
            input.authorization,
            &registration,
            Utc::now(),
        )
        .await
        .map_err(service_storage_error)?;
    match committed {
        soland_storage::PushRegistrationHandoffReceiptWrite::Stored(record)
        | soland_storage::PushRegistrationHandoffReceiptWrite::ExactReplay(record) => {
            outcome_from_record(&record)
        }
    }
}

fn canonical_gateway_origin(raw: &str) -> Result<WebOrigin, AppError> {
    let url = reqwest::Url::parse(raw)
        .map_err(|_| AppError::param_invalid("invalid push gateway URL"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(AppError::param_invalid("invalid push gateway URL"));
    }
    WebOrigin::new(url.origin().ascii_serialization())
        .map_err(|_| AppError::param_invalid("invalid push gateway URL"))
}

async fn resolve_trusted_gateway(
    state: &AppState,
    origin: &WebOrigin,
) -> Result<
    (
        TrustedPushGateway,
        soland_services::service_route::ResolvedServiceRoute,
    ),
    AppError,
> {
    let registry = state.trusted_push_gateways();
    let gateway = registry
        .get(origin)
        .cloned()
        .ok_or_else(|| handoff_unavailable("Gateway origin is not onboarded", origin))?;
    let resolver = state
        .service_route_resolver()
        .map_err(|error| handoff_unavailable("Gateway route resolver unavailable", error))?;
    let now = Utc::now();
    let route = match resolver
        .resolve_route(
            gateway.service_id(),
            ServiceKind::PushGateway.as_str(),
            now,
            false,
        )
        .await
    {
        Ok(route) => route,
        Err(soland_services::ServiceError::NotFound(_)) => {
            let base = arkret_models_identity::service_identity::CanonicalServiceUrl::canonicalize(
                origin.as_str(),
            )
            .map_err(|error| handoff_unavailable("Gateway origin is invalid", error))?;
            let carrier = arkret_models_identity::ServiceResolutionCarrier::ResolutionUrl {
                resolution_url: format!(
                    "{}{}",
                    base,
                    arkret_models_identity::canonical_service_resolution_path(gateway.service_id())
                        .trim_start_matches('/')
                ),
            };
            carrier
                .validate_shape(gateway.service_id())
                .map_err(|error| handoff_unavailable("Gateway carrier is invalid", error))?;
            resolver
                .resolve_carrier(
                    &carrier,
                    gateway.service_id(),
                    ServiceKind::PushGateway.as_str(),
                    now,
                )
                .await
                .map_err(|error| handoff_unavailable("Gateway route verification failed", error))?;
            resolver
                .resolve_route(
                    gateway.service_id(),
                    ServiceKind::PushGateway.as_str(),
                    now,
                    false,
                )
                .await
                .map_err(|error| handoff_unavailable("Gateway route unavailable", error))?
        }
        Err(error) => {
            return Err(handoff_unavailable(
                "Gateway route verification failed",
                error,
            ));
        }
    };
    registry
        .authorize_route(origin, &route, now)
        .map_err(|error| handoff_unavailable("Gateway route is not trusted", error))?;
    Ok((gateway, route))
}

fn random_registration_id() -> Result<PushRegistrationId, AppError> {
    PushRegistrationId::new(URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>())).map_err(|error| {
        AppError::internal(format!(
            "generated push registration id is invalid: {error}"
        ))
    })
}

fn local_registration(
    intent: &PushRegistrationHandoffIntentRecord,
    request: &PushRegistrationHandoffRequestBody,
    account_id: &AccountId,
    push_route_id: &str,
    origin: &WebOrigin,
) -> Result<PushRegistrationRecord, AppError> {
    let PushRegistrationHandoffRequestBody::Active {
        registration_id,
        push_target_id,
        device_id,
        push_key,
        platform,
        app_id,
        visible_notification_opt_in,
        expires_at,
        ..
    } = request
    else {
        return Err(AppError::internal(
            "revoked Push Gateway intent cannot complete active registration",
        ));
    };
    Ok(PushRegistrationRecord {
        registration_id: arkret_wire::OpaqueLocalId::new(registration_id.as_str().to_owned())
            .map_err(|error| {
                AppError::internal(format!("push registration id projection failed: {error}"))
            })?,
        account_id: account_id.clone(),
        device_id: device_id.clone(),
        push_gateway: format!("{origin}/"),
        push_key: push_key.clone(),
        platform: platform.clone(),
        app_id: app_id.clone(),
        visible_notification_opt_in: *visible_notification_opt_in,
        push_route_id: push_route_id.to_owned(),
        push_target_id: push_target_id.clone(),
        salt_epoch_id: super::push::push_target_salt_epoch_id_at(intent.created_at),
        expires_at: *expires_at,
        retained_push_targets: Vec::new(),
    })
}

fn outcome_from_record(
    record: &PushRegistrationHandoffIntentRecord,
) -> Result<PushRegisterDeviceOutcome, AppError> {
    record.validate().map_err(persistence_error)?;
    if record.status != PushRegistrationHandoffIntentStatus::ReceiptVerified
        || record.receipt.is_none()
    {
        return Err(AppError::internal(
            "push registration outcome requested before receipt commit",
        ));
    }
    let request = record.request().map_err(persistence_error)?;
    let PushRegistrationHandoffRequestBody::Active {
        registration_id,
        push_target_id,
        expires_at,
        ..
    } = request
    else {
        return Err(AppError::internal(
            "revoked Push Gateway intent cannot produce active registration outcome",
        ));
    };
    Ok(PushRegisterDeviceOutcome {
        push_target_id,
        registration_id: Some(
            arkret_wire::OpaqueLocalId::new(registration_id.into_string()).map_err(|error| {
                AppError::internal(format!("push registration id projection failed: {error}"))
            })?,
        ),
        expires_at,
    })
}

fn service_storage_error(error: soland_services::ServiceError) -> AppError {
    let detail = error.to_string();
    if error.is_conflict_kind() {
        AppError::conflict("push registration state changed concurrently")
            .with_private_detail(detail)
    } else {
        AppError::internal("push registration persistence failed").with_private_detail(detail)
    }
}

fn persistence_error(error: soland_storage::PersistenceError) -> AppError {
    let is_conflict = matches!(&error, soland_storage::PersistenceError::Conflict(_));
    let detail = error.to_string();
    if is_conflict {
        AppError::conflict("push registration state changed concurrently")
            .with_private_detail(detail)
    } else {
        AppError::internal("push registration persistence failed").with_private_detail(detail)
    }
}

fn handoff_unavailable(stage: &'static str, _error: impl std::fmt::Display) -> AppError {
    tracing::warn!(stage, "public Push Gateway registration handoff failed");
    AppError::new(
        ErrorCode::DependencyMissing,
        "public Push Gateway registration is unavailable",
    )
    .with_private_detail(stage)
}

#[cfg(test)]
mod tests {
    use arkret_models_integration::PushRegistrationHandoffState;
    use arkret_wire::{Audience, DeviceId, DidCoreId, DidUrl, Hash, PayloadProof};
    use serde_json::json;

    use super::*;

    fn request(registration_id: &str) -> PushRegistrationHandoffRequestBody {
        serde_json::from_value(json!({
            "registration_id": registration_id,
            "push_target_id": "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
            "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
            "state": "active",
            "push_key": "provider-secret",
            "platform": "desktop",
            "app_id": "inkson",
            "visible_notification_opt_in": false
        }))
        .unwrap()
    }

    fn client_body() -> PushRegisterDeviceRequestBody {
        serde_json::from_value(json!({
            "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
            "push_gateway_url": "https://push.example/_arkret/edge/push/notify",
            "push_key": "provider-secret",
            "platform": "desktop",
            "app_id": "inkson",
            "visible_notification_opt_in": false
        }))
        .unwrap()
    }

    fn record(status: PushRegistrationHandoffIntentStatus) -> PushRegistrationHandoffIntentRecord {
        let source = DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let destination = DidCoreId::new("ak:did_core:web:push.example").unwrap();
        let request = request("registration_0123456789abcdef");
        let digest = Hash::new(format!("sha256:{}", "2".repeat(64))).unwrap();
        let now = DateTime::parse_from_rfc3339("2026-09-22T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut record = PushRegistrationHandoffIntentRecord::prepare(
            source.clone(),
            PushRegistrationHandoffRouteLocator {
                account_id: AccountId::new(
                    DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                    source.clone(),
                ),
                device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap(),
                push_route_id: "inkson".to_owned(),
                destination_gateway_id: destination.clone(),
            },
            digest,
            &request,
            now,
        )
        .unwrap();
        if status == PushRegistrationHandoffIntentStatus::ReceiptVerified {
            let mut receipt = arkret_models_integration::PushRegistrationInstallationReceipt {
                registration_id: request.registration_id().clone(),
                push_target_id: request.push_target_id().clone(),
                device_id: request.device_id().clone(),
                state: PushRegistrationHandoffState::Active,
                request_digest: request.request_digest().unwrap(),
                source_station_id: source,
                destination_gateway_id: destination,
                stored_at: now,
                proof: PayloadProof {
                    kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
                    verification_method: DidUrl::new("did:web:push.example#receipt").unwrap(),
                    payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                    created_at: now,
                    domain: None,
                    audience: Some(Audience::Single(
                        "ak:did_core:web:station.example".to_owned(),
                    )),
                    proof_purpose: None,
                    jws: "fixture..signature".to_owned(),
                },
            };
            receipt.proof.payload_digest = receipt.expected_payload_digest().unwrap();
            record.status = status;
            record.receipt = Some(receipt);
        }
        record
    }

    #[test]
    fn retry_replays_pending_and_returns_verified_without_allocating_another_id() {
        let pending = record(PushRegistrationHandoffIntentStatus::AwaitingReceipt);
        let digest = pending.client_input_digest.clone();
        assert!(matches!(
            plan_active_push_registration(Some(pending), &digest).unwrap(),
            ActivePushRegistrationPlan::ReplayPending(_)
        ));

        let verified = record(PushRegistrationHandoffIntentStatus::ReceiptVerified);
        let durable_outcome = outcome_from_record(&verified).unwrap();
        assert_eq!(
            durable_outcome.registration_id.as_ref().unwrap().as_str(),
            verified.registration_id.as_str()
        );
        assert!(matches!(
            plan_active_push_registration(Some(verified), &digest).unwrap(),
            ActivePushRegistrationPlan::ReturnVerified(_)
        ));
    }

    #[test]
    fn changed_input_conflicts_while_pending_and_supersedes_only_after_verification() {
        let changed = Hash::new(format!("sha256:{}", "3".repeat(64))).unwrap();
        let pending = record(PushRegistrationHandoffIntentStatus::AwaitingReceipt);
        assert!(plan_active_push_registration(Some(pending), &changed).is_err());

        let verified = record(PushRegistrationHandoffIntentStatus::ReceiptVerified);
        let expected = verified.registration_id.clone();
        match plan_active_push_registration(Some(verified), &changed).unwrap() {
            ActivePushRegistrationPlan::Create { predecessor } => {
                assert_eq!(predecessor, Some(expected));
            }
            _ => panic!("changed verified input must create a successor"),
        }
    }

    #[test]
    fn registration_ids_have_full_random_128_bit_payload_and_origins_are_canonical() {
        let first = random_registration_id().unwrap();
        let second = random_registration_id().unwrap();
        assert_eq!(first.as_str().len(), 22);
        assert_ne!(first, second);
        assert_eq!(
            canonical_gateway_origin("https://push.example/_arkret/edge/push/notify")
                .unwrap()
                .as_str(),
            "https://push.example"
        );
        assert!(canonical_gateway_origin("http://push.example/notify").is_err());
        assert!(canonical_gateway_origin("https://user@push.example/notify").is_err());
    }

    #[test]
    fn client_digest_binds_local_identity_destination_and_desired_route_semantics() {
        let source = DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let account = AccountId::new(
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            source,
        );
        let destination = DidCoreId::new("ak:did_core:web:push.example").unwrap();
        let origin = WebOrigin::new("https://push.example").unwrap();
        let body = client_body();
        let target = arkret_identifiers::PushTargetId::new(
            "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
        )
        .unwrap();
        let digest = active_push_registration_client_input_digest(
            &account,
            &body,
            "inkson",
            &origin,
            &destination,
            &target,
        )
        .unwrap();

        let mut changed = body.clone();
        changed.visible_notification_opt_in = true;
        assert_ne!(
            digest,
            active_push_registration_client_input_digest(
                &account,
                &changed,
                "inkson",
                &origin,
                &destination,
                &target,
            )
            .unwrap()
        );
        assert_ne!(
            digest,
            active_push_registration_client_input_digest(
                &account,
                &body,
                "inkson.voip",
                &origin,
                &destination,
                &target
            )
            .unwrap()
        );
        let other_destination = DidCoreId::new("ak:did_core:web:push-2.example").unwrap();
        assert_ne!(
            digest,
            active_push_registration_client_input_digest(
                &account,
                &body,
                "inkson",
                &origin,
                &other_destination,
                &target
            )
            .unwrap()
        );
        let next_epoch_target = arkret_identifiers::PushTargetId::new(
            "ak:pseudonym:push:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
        .unwrap();
        assert_ne!(
            digest,
            active_push_registration_client_input_digest(
                &account,
                &body,
                "inkson",
                &origin,
                &destination,
                &next_epoch_target
            )
            .unwrap(),
            "salt-epoch target rotation must create a successor handoff"
        );
    }

    #[test]
    fn remote_error_detail_is_not_logged_or_exposed() {
        let error = handoff_unavailable(
            "Gateway request failed",
            "remote body echoed provider-secret",
        );
        assert_eq!(
            error.message.as_ref(),
            "public Push Gateway registration is unavailable"
        );
        assert_eq!(
            error.private_detail.as_deref(),
            Some("Gateway request failed")
        );
        assert!(!format!("{error:?}").contains("provider-secret"));
    }
}
