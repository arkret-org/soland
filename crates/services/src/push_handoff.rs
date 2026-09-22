//! Transport-independent public Push Gateway handoff retry planning.

use arkret::PushRegisterDeviceRequestBody;
use arkret_identifiers::PushTargetId;
use arkret_wire::{AccountId, DidCoreId, Hash, WebOrigin};
use soland_storage::{PushRegistrationHandoffIntentRecord, PushRegistrationHandoffIntentStatus};

use crate::{ServiceError, ServiceResult};

pub fn active_push_registration_client_input_digest(
    account_id: &AccountId,
    body: &PushRegisterDeviceRequestBody,
    push_route_id: &str,
    origin: &WebOrigin,
    destination_gateway_id: &DidCoreId,
) -> ServiceResult<Hash> {
    let input = serde_json::json!({
        "account_id": account_id,
        "device_id": body.device_id,
        "push_route_id": push_route_id,
        "destination_gateway_id": destination_gateway_id,
        "gateway_origin": origin,
        "push_key": body.push_key,
        "platform": body.platform,
        "app_id": body.app_id,
        "visible_notification_opt_in": body.visible_notification_opt_in,
    });
    let digest = arkret_canonical::canonical_sha256(&input)
        .map_err(|error| ServiceError::Internal(error.to_string()))?;
    Hash::new(digest).map_err(|error| ServiceError::Internal(error.to_string()))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActivePushRegistrationPlan {
    ReturnVerified(PushRegistrationHandoffIntentRecord),
    ReplayPending(PushRegistrationHandoffIntentRecord),
    Create {
        predecessor: Option<arkret::PushRegistrationId>,
    },
}

pub fn plan_active_push_registration(
    existing: Option<PushRegistrationHandoffIntentRecord>,
    client_input_digest: &Hash,
    current_push_target_id: &PushTargetId,
) -> ServiceResult<ActivePushRegistrationPlan> {
    let Some(existing) = existing else {
        return Ok(ActivePushRegistrationPlan::Create { predecessor: None });
    };
    let request = existing.request()?;
    if request.state() == arkret::PushRegistrationHandoffState::Revoked {
        return match existing.status {
            PushRegistrationHandoffIntentStatus::AwaitingReceipt => Err(ServiceError::Conflict(
                "cas_conflict: public Push Gateway revocation is awaiting a receipt".to_owned(),
            )),
            PushRegistrationHandoffIntentStatus::ReceiptVerified => {
                Ok(ActivePushRegistrationPlan::Create {
                    predecessor: Some(existing.registration_id),
                })
            }
        };
    }
    match existing.status {
        PushRegistrationHandoffIntentStatus::AwaitingReceipt => {
            if &existing.client_input_digest != client_input_digest {
                return Err(ServiceError::Conflict(
                    "cas_conflict: another public Push Gateway registration is awaiting a receipt"
                        .to_owned(),
                ));
            }
            Ok(ActivePushRegistrationPlan::ReplayPending(existing))
        }
        PushRegistrationHandoffIntentStatus::ReceiptVerified => {
            if &existing.client_input_digest == client_input_digest
                && request.push_target_id() == current_push_target_id
            {
                Ok(ActivePushRegistrationPlan::ReturnVerified(existing))
            } else {
                Ok(ActivePushRegistrationPlan::Create {
                    predecessor: Some(existing.registration_id),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use arkret::PushRegistrationHandoffRequestBody;
    use arkret_identifiers::PushTargetId;
    use arkret_wire::{AccountId, DeviceId, DidCoreId};
    use chrono::{DateTime, Utc};
    use serde_json::json;
    use soland_storage::PushRegistrationHandoffRouteLocator;

    use super::*;

    fn device_authorization(
        source: &DidCoreId,
        device_id: &DeviceId,
    ) -> soland_storage::DeviceRevocationGateSelector {
        let event_id =
            arkret_wire::EventId::new("ak:event:AcIMom-0qqAXx_hmDJfxxaUJb_oJ64S3ARW1-WKFDCoD")
                .unwrap();
        soland_storage::DeviceRevocationGateSelector {
            principal_id: DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            station_id: source.clone(),
            device_id: device_id.as_str().to_owned(),
            authorization_ref: arkret_wire::CommittedEventRef {
                commit_id: arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
                    event_id.as_str().as_bytes(),
                )),
                stream_ref: arkret_wire::CommitStreamRef::Realm {
                    realm_id: arkret_wire::RealmId::new(
                        "ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir",
                    )
                    .unwrap(),
                },
                stream_position: 1,
                event_id,
            },
        }
    }

    fn record(status: PushRegistrationHandoffIntentStatus) -> PushRegistrationHandoffIntentRecord {
        let source = DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let destination = DidCoreId::new("ak:did_core:web:push.example").unwrap();
        let request: PushRegistrationHandoffRequestBody = serde_json::from_value(json!({
            "registration_id": "registration_0123456789abcdef",
            "push_target_id": "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
            "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
            "state": "active",
            "push_key": "provider-secret",
            "platform": "desktop",
            "app_id": "inkson",
            "visible_notification_opt_in": false
        }))
        .unwrap();
        let device_id = request.device_id().clone();
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
                destination_gateway_id: destination,
            },
            device_authorization(&source, &device_id),
            digest,
            &request,
            now,
        )
        .unwrap();
        if status == PushRegistrationHandoffIntentStatus::ReceiptVerified {
            record.status = status;
        }
        record
    }

    fn revoked_record(
        status: PushRegistrationHandoffIntentStatus,
    ) -> PushRegistrationHandoffIntentRecord {
        let active = record(PushRegistrationHandoffIntentStatus::AwaitingReceipt);
        let request = active.request().unwrap();
        let revoked = PushRegistrationHandoffRequestBody::Revoked {
            registration_id: active.registration_id.clone(),
            push_target_id: request.push_target_id().clone(),
            device_id: request.device_id().clone(),
        };
        let mut record = PushRegistrationHandoffIntentRecord::prepare(
            active.source_station_id,
            active.local_route,
            active.device_authorization,
            active.client_input_digest,
            &revoked,
            active.created_at,
        )
        .unwrap();
        record.status = status;
        record
    }

    #[test]
    fn pending_cross_epoch_replays_stored_body_but_verified_cross_epoch_supersedes() {
        let next_epoch_target =
            PushTargetId::new("ak:pseudonym:push:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                .unwrap();
        let pending = record(PushRegistrationHandoffIntentStatus::AwaitingReceipt);
        let pending_body = pending.canonical_request.clone();
        let digest = pending.client_input_digest.clone();
        match plan_active_push_registration(Some(pending), &digest, &next_epoch_target).unwrap() {
            ActivePushRegistrationPlan::ReplayPending(record) => {
                assert_eq!(record.canonical_request, pending_body)
            }
            other => panic!("pending cross-epoch retry did not replay: {other:?}"),
        }

        let verified = record(PushRegistrationHandoffIntentStatus::ReceiptVerified);
        let predecessor = verified.registration_id.clone();
        assert_eq!(
            plan_active_push_registration(Some(verified), &digest, &next_epoch_target).unwrap(),
            ActivePushRegistrationPlan::Create {
                predecessor: Some(predecessor)
            }
        );
    }

    #[test]
    fn exact_pending_replays_and_changed_pending_conflicts() {
        let pending = record(PushRegistrationHandoffIntentStatus::AwaitingReceipt);
        let digest = pending.client_input_digest.clone();
        let target = pending.request().unwrap().push_target_id().clone();
        assert!(matches!(
            plan_active_push_registration(Some(pending.clone()), &digest, &target).unwrap(),
            ActivePushRegistrationPlan::ReplayPending(_)
        ));
        let changed = Hash::new(format!("sha256:{}", "3".repeat(64))).unwrap();
        assert!(plan_active_push_registration(Some(pending), &changed, &target).is_err());
    }

    #[test]
    fn exact_verified_returns_and_changed_verified_supersedes() {
        let verified = record(PushRegistrationHandoffIntentStatus::ReceiptVerified);
        let digest = verified.client_input_digest.clone();
        let target = verified.request().unwrap().push_target_id().clone();
        assert!(matches!(
            plan_active_push_registration(Some(verified.clone()), &digest, &target).unwrap(),
            ActivePushRegistrationPlan::ReturnVerified(_)
        ));
        let changed = Hash::new(format!("sha256:{}", "3".repeat(64))).unwrap();
        let predecessor = verified.registration_id.clone();
        assert_eq!(
            plan_active_push_registration(Some(verified), &changed, &target).unwrap(),
            ActivePushRegistrationPlan::Create {
                predecessor: Some(predecessor)
            }
        );
    }

    #[test]
    fn revoked_pending_waits_but_verified_revoke_creates_successor() {
        let pending = revoked_record(PushRegistrationHandoffIntentStatus::AwaitingReceipt);
        let digest = pending.client_input_digest.clone();
        let target = pending.request().unwrap().push_target_id().clone();
        assert!(plan_active_push_registration(Some(pending), &digest, &target).is_err());

        let verified = revoked_record(PushRegistrationHandoffIntentStatus::ReceiptVerified);
        let predecessor = verified.registration_id.clone();
        assert_eq!(
            plan_active_push_registration(Some(verified), &digest, &target).unwrap(),
            ActivePushRegistrationPlan::Create {
                predecessor: Some(predecessor)
            }
        );
    }
}
