use arkret_models_integration::{
    PushRegistrationHandoffRequestBody, PushRegistrationHandoffState, PushRegistrationId,
    PushRegistrationInstallationReceipt,
};
use arkret_wire::{DidCoreId, Hash};
use chrono::{DateTime, Utc};

use super::{PersistenceError, PersistenceResult, async_trait};

/// Local delivery state for one durable public Push Gateway desired intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PushRegistrationHandoffIntentStatus {
    AwaitingReceipt,
    ReceiptVerified,
}

impl PushRegistrationHandoffIntentStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AwaitingReceipt => "awaiting_receipt",
            Self::ReceiptVerified => "receipt_verified",
        }
    }
}

/// Exact desired state retained until a Gateway receipt has been verified and
/// committed. `canonical_request` is the body that must be replayed after a
/// timeout or process restart; callers must never regenerate a replacement
/// body for the same registration identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PushRegistrationHandoffIntentRecord {
    pub source_station_id: DidCoreId,
    pub destination_gateway_id: DidCoreId,
    pub registration_id: PushRegistrationId,
    pub desired_state: PushRegistrationHandoffState,
    pub request_digest: Hash,
    pub canonical_request: Vec<u8>,
    pub status: PushRegistrationHandoffIntentStatus,
    pub receipt: Option<PushRegistrationInstallationReceipt>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl PushRegistrationHandoffIntentRecord {
    pub fn prepare(
        source_station_id: DidCoreId,
        destination_gateway_id: DidCoreId,
        request: &PushRegistrationHandoffRequestBody,
        now: DateTime<Utc>,
    ) -> PersistenceResult<Self> {
        request
            .validate()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        let canonical_request = arkret_canonical::canonical::canonical_json_bytes(request)
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        let request_digest = request
            .request_digest()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        Ok(Self {
            source_station_id,
            destination_gateway_id,
            registration_id: request.registration_id().clone(),
            desired_state: request.state(),
            request_digest,
            canonical_request,
            status: PushRegistrationHandoffIntentStatus::AwaitingReceipt,
            receipt: None,
            created_at: now,
            updated_at: now,
        })
    }

    pub fn request(&self) -> PersistenceResult<PushRegistrationHandoffRequestBody> {
        let request: PushRegistrationHandoffRequestBody =
            serde_json::from_slice(&self.canonical_request).map_err(|error| {
                PersistenceError::Internal(format!(
                    "stored push registration handoff request is invalid: {error}"
                ))
            })?;
        request.validate().map_err(|error| {
            PersistenceError::Internal(format!(
                "stored push registration handoff request is invalid: {error}"
            ))
        })?;
        let canonical = arkret_canonical::canonical::canonical_json_bytes(&request)
            .map_err(PersistenceError::database)?;
        let digest = request
            .request_digest()
            .map_err(PersistenceError::database)?;
        if canonical != self.canonical_request
            || digest != self.request_digest
            || request.registration_id() != &self.registration_id
            || request.state() != self.desired_state
        {
            return Err(PersistenceError::Internal(
                "stored push registration handoff request binding mismatch".to_owned(),
            ));
        }
        Ok(request)
    }

    pub fn validate(&self) -> PersistenceResult<()> {
        if self.updated_at < self.created_at {
            return Err(PersistenceError::Internal(
                "stored push registration handoff timestamp regressed".to_owned(),
            ));
        }
        let request = self.request()?;
        match (self.status, &self.receipt) {
            (PushRegistrationHandoffIntentStatus::AwaitingReceipt, None) => Ok(()),
            (PushRegistrationHandoffIntentStatus::ReceiptVerified, Some(receipt)) => receipt
                .validate_for_handoff(
                    &request,
                    &self.source_station_id,
                    &self.destination_gateway_id,
                )
                .map_err(|error| {
                    PersistenceError::Internal(format!(
                        "stored push registration handoff receipt binding mismatch: {error}"
                    ))
                }),
            _ => Err(PersistenceError::Internal(
                "stored push registration handoff status/receipt mismatch".to_owned(),
            )),
        }
    }

    #[must_use]
    pub fn same_desired_intent(&self, candidate: &Self) -> bool {
        self.source_station_id == candidate.source_station_id
            && self.destination_gateway_id == candidate.destination_gateway_id
            && self.registration_id == candidate.registration_id
            && self.desired_state == candidate.desired_state
            && self.request_digest == candidate.request_digest
            && self.canonical_request == candidate.canonical_request
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PushRegistrationHandoffIntentWrite {
    Created(PushRegistrationHandoffIntentRecord),
    ExactReplay(PushRegistrationHandoffIntentRecord),
    AdvancedToRevoked(PushRegistrationHandoffIntentRecord),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PushRegistrationHandoffReceiptWrite {
    Stored(PushRegistrationHandoffIntentRecord),
    ExactReplay(PushRegistrationHandoffIntentRecord),
}

/// Apply one desired-state write under the durable registration row lock.
/// Active details are immutable; the only non-replay transition is an exact
/// installation identity moving from active to terminal revoked. That move
/// replaces the request digest/body and clears any active receipt so a late
/// active response cannot complete the revoke intent.
pub fn apply_push_registration_desired_intent(
    stored: &PushRegistrationHandoffIntentRecord,
    candidate: &PushRegistrationHandoffIntentRecord,
) -> PersistenceResult<PushRegistrationHandoffIntentWrite> {
    stored.validate()?;
    candidate.validate()?;
    if stored.same_desired_intent(candidate) {
        return Ok(PushRegistrationHandoffIntentWrite::ExactReplay(
            stored.clone(),
        ));
    }
    let stored_request = stored.request()?;
    let candidate_request = candidate.request()?;
    if stored.desired_state == PushRegistrationHandoffState::Active
        && candidate.desired_state == PushRegistrationHandoffState::Revoked
        && stored.source_station_id == candidate.source_station_id
        && stored.destination_gateway_id == candidate.destination_gateway_id
        && stored.registration_id == candidate.registration_id
        && stored_request.push_target_id() == candidate_request.push_target_id()
        && stored_request.device_id() == candidate_request.device_id()
    {
        let mut revoked = candidate.clone();
        revoked.created_at = stored.created_at;
        revoked.updated_at = candidate.updated_at;
        revoked.status = PushRegistrationHandoffIntentStatus::AwaitingReceipt;
        revoked.receipt = None;
        revoked.validate()?;
        return Ok(PushRegistrationHandoffIntentWrite::AdvancedToRevoked(
            revoked,
        ));
    }
    Err(PersistenceError::Conflict(
        "cas_conflict: push registration handoff identity already has another desired intent"
            .to_owned(),
    ))
}

/// Apply a receipt that the caller has already verified with the formal SDK
/// detached-JWS verifier. This layer re-checks every request/receipt binding
/// before making the receipt durable, but intentionally does not resolve or
/// trust Gateway key material itself.
pub fn apply_verified_push_registration_receipt(
    record: &PushRegistrationHandoffIntentRecord,
    expected_request_digest: &Hash,
    receipt: &PushRegistrationInstallationReceipt,
    now: DateTime<Utc>,
) -> PersistenceResult<PushRegistrationHandoffReceiptWrite> {
    record.validate()?;
    if &record.request_digest != expected_request_digest {
        return Err(PersistenceError::Conflict(
            "cas_conflict: push registration handoff request digest changed".to_owned(),
        ));
    }
    let request = record.request()?;
    receipt
        .validate_for_handoff(
            &request,
            &record.source_station_id,
            &record.destination_gateway_id,
        )
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if let Some(stored) = &record.receipt {
        if stored == receipt {
            return Ok(PushRegistrationHandoffReceiptWrite::ExactReplay(
                record.clone(),
            ));
        }
        return Err(PersistenceError::Conflict(
            "cas_conflict: push registration handoff receipt differs from the verified receipt"
                .to_owned(),
        ));
    }
    let mut committed = record.clone();
    committed.status = PushRegistrationHandoffIntentStatus::ReceiptVerified;
    committed.receipt = Some(receipt.clone());
    committed.updated_at = now;
    committed.validate()?;
    Ok(PushRegistrationHandoffReceiptWrite::Stored(committed))
}

#[async_trait]
pub trait PushRegistrationHandoffStore: Send + Sync {
    async fn ensure_desired_intent(
        &self,
        source_station_id: &DidCoreId,
        destination_gateway_id: &DidCoreId,
        request: &PushRegistrationHandoffRequestBody,
        now: DateTime<Utc>,
    ) -> PersistenceResult<PushRegistrationHandoffIntentWrite>;

    async fn get_intent(
        &self,
        source_station_id: &DidCoreId,
        registration_id: &PushRegistrationId,
    ) -> PersistenceResult<Option<PushRegistrationHandoffIntentRecord>>;

    async fn commit_verified_receipt(
        &self,
        source_station_id: &DidCoreId,
        registration_id: &PushRegistrationId,
        expected_request_digest: &Hash,
        receipt: &PushRegistrationInstallationReceipt,
        now: DateTime<Utc>,
    ) -> PersistenceResult<PushRegistrationHandoffReceiptWrite>;
}

#[cfg(test)]
mod tests {
    use arkret_wire::{Audience, DidUrl, PayloadProof};
    use serde_json::json;

    use super::*;

    fn active_request() -> PushRegistrationHandoffRequestBody {
        serde_json::from_value(json!({
            "registration_id": "registration_0123456789abcdef",
            "push_target_id": "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
            "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
            "state": "active",
            "push_key": "provider-secret",
            "platform": "apns",
            "app_id": "com.example.app",
            "visible_notification_opt_in": false
        }))
        .unwrap()
    }

    fn identities() -> (DidCoreId, DidCoreId) {
        (
            DidCoreId::new("ak:did_core:web:source.example").unwrap(),
            DidCoreId::new("ak:did_core:web:gateway.example").unwrap(),
        )
    }

    fn receipt_for(
        request: &PushRegistrationHandoffRequestBody,
        source: &DidCoreId,
        destination: &DidCoreId,
        stored_at: DateTime<Utc>,
    ) -> PushRegistrationInstallationReceipt {
        let mut receipt = PushRegistrationInstallationReceipt {
            registration_id: request.registration_id().clone(),
            push_target_id: request.push_target_id().clone(),
            device_id: request.device_id().clone(),
            state: request.state(),
            request_digest: request.request_digest().unwrap(),
            source_station_id: source.clone(),
            destination_gateway_id: destination.clone(),
            stored_at,
            proof: PayloadProof {
                kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
                verification_method: DidUrl::new("did:web:gateway.example#push-receipt-key")
                    .unwrap(),
                payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                created_at: stored_at,
                domain: None,
                audience: Some(Audience::Single(source.as_str().to_owned())),
                proof_purpose: None,
                jws: "fixture..signature".to_owned(),
            },
        };
        receipt.proof.payload_digest = receipt.expected_payload_digest().unwrap();
        receipt
    }

    #[test]
    fn prepares_exact_active_and_revoked_desired_intents() {
        let (source, destination) = identities();
        let now = Utc::now();
        let active = active_request();
        let active_record = PushRegistrationHandoffIntentRecord::prepare(
            source.clone(),
            destination.clone(),
            &active,
            now,
        )
        .unwrap();
        assert_eq!(
            active_record.desired_state,
            PushRegistrationHandoffState::Active
        );
        assert_eq!(active_record.request().unwrap(), active);
        assert_eq!(
            active_record.request_digest,
            active.request_digest().unwrap()
        );

        let revoked: PushRegistrationHandoffRequestBody = serde_json::from_value(json!({
            "registration_id": "registration_0123456789abcdef",
            "push_target_id": "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
            "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
            "state": "revoked"
        }))
        .unwrap();
        let revoked_record =
            PushRegistrationHandoffIntentRecord::prepare(source, destination, &revoked, now)
                .unwrap();
        assert_eq!(
            revoked_record.desired_state,
            PushRegistrationHandoffState::Revoked
        );
        assert_ne!(
            revoked_record.canonical_request,
            active_record.canonical_request
        );
        assert!(!active_record.same_desired_intent(&revoked_record));
    }

    #[test]
    fn verified_receipt_commit_is_cas_and_exactly_replayable() {
        let (source, destination) = identities();
        let request = active_request();
        let prepared_at = Utc::now();
        let record = PushRegistrationHandoffIntentRecord::prepare(
            source.clone(),
            destination.clone(),
            &request,
            prepared_at,
        )
        .unwrap();
        let receipt = receipt_for(
            &request,
            &source,
            &destination,
            prepared_at + chrono::Duration::seconds(1),
        );
        let stored = match apply_verified_push_registration_receipt(
            &record,
            &record.request_digest,
            &receipt,
            prepared_at + chrono::Duration::seconds(2),
        )
        .unwrap()
        {
            PushRegistrationHandoffReceiptWrite::Stored(record) => record,
            PushRegistrationHandoffReceiptWrite::ExactReplay(_) => panic!("first commit replayed"),
        };
        assert_eq!(
            stored.status,
            PushRegistrationHandoffIntentStatus::ReceiptVerified
        );
        assert_eq!(stored.receipt.as_ref(), Some(&receipt));
        assert!(matches!(
            apply_verified_push_registration_receipt(
                &stored,
                &stored.request_digest,
                &receipt,
                prepared_at + chrono::Duration::seconds(3),
            )
            .unwrap(),
            PushRegistrationHandoffReceiptWrite::ExactReplay(_)
        ));

        let wrong_digest = Hash::new(format!("sha256:{}", "f".repeat(64))).unwrap();
        assert!(matches!(
            apply_verified_push_registration_receipt(
                &stored,
                &wrong_digest,
                &receipt,
                prepared_at + chrono::Duration::seconds(3),
            ),
            Err(PersistenceError::Conflict(_))
        ));
    }

    #[test]
    fn revoke_replaces_active_and_rejects_late_active_receipt() {
        let (source, destination) = identities();
        let active = active_request();
        let prepared_at = Utc::now();
        let active_record = PushRegistrationHandoffIntentRecord::prepare(
            source.clone(),
            destination.clone(),
            &active,
            prepared_at,
        )
        .unwrap();
        let revoked: PushRegistrationHandoffRequestBody = serde_json::from_value(json!({
            "registration_id": active.registration_id(),
            "push_target_id": active.push_target_id(),
            "device_id": active.device_id(),
            "state": "revoked"
        }))
        .unwrap();
        let revoked_candidate = PushRegistrationHandoffIntentRecord::prepare(
            source.clone(),
            destination.clone(),
            &revoked,
            prepared_at + chrono::Duration::seconds(1),
        )
        .unwrap();
        let pending_revoked =
            match apply_push_registration_desired_intent(&active_record, &revoked_candidate)
                .unwrap()
            {
                PushRegistrationHandoffIntentWrite::AdvancedToRevoked(record) => record,
                other => panic!("expected active-to-revoked transition, got {other:?}"),
            };
        assert_eq!(pending_revoked.request().unwrap(), revoked);
        assert!(pending_revoked.receipt.is_none());

        let wrong_device_revoke: PushRegistrationHandoffRequestBody =
            serde_json::from_value(json!({
                "registration_id": active.registration_id(),
                "push_target_id": active.push_target_id(),
                "device_id": "ak:device:01904100-0000-7000-8000-000000000002",
                "state": "revoked"
            }))
            .unwrap();
        let wrong_device_revoke = PushRegistrationHandoffIntentRecord::prepare(
            source.clone(),
            destination.clone(),
            &wrong_device_revoke,
            prepared_at + chrono::Duration::seconds(1),
        )
        .unwrap();
        assert!(matches!(
            apply_push_registration_desired_intent(&active_record, &wrong_device_revoke),
            Err(PersistenceError::Conflict(_))
        ));

        let active_receipt = receipt_for(
            &active,
            &source,
            &destination,
            prepared_at + chrono::Duration::seconds(1),
        );
        let confirmed_active = match apply_verified_push_registration_receipt(
            &active_record,
            &active_record.request_digest,
            &active_receipt,
            prepared_at + chrono::Duration::seconds(1),
        )
        .unwrap()
        {
            PushRegistrationHandoffReceiptWrite::Stored(record) => record,
            PushRegistrationHandoffReceiptWrite::ExactReplay(_) => panic!("first commit replayed"),
        };
        let revoked_record =
            match apply_push_registration_desired_intent(&confirmed_active, &revoked_candidate)
                .unwrap()
            {
                PushRegistrationHandoffIntentWrite::AdvancedToRevoked(record) => record,
                other => panic!("expected confirmed active revoke, got {other:?}"),
            };
        assert_eq!(revoked_record.request().unwrap(), revoked);
        assert!(revoked_record.receipt.is_none());
        assert!(matches!(
            apply_push_registration_desired_intent(&revoked_record, &revoked_candidate).unwrap(),
            PushRegistrationHandoffIntentWrite::ExactReplay(_)
        ));
        assert!(matches!(
            apply_push_registration_desired_intent(&revoked_record, &active_record),
            Err(PersistenceError::Conflict(_))
        ));

        let mut other_active = active.clone();
        let PushRegistrationHandoffRequestBody::Active {
            visible_notification_opt_in,
            ..
        } = &mut other_active
        else {
            unreachable!()
        };
        *visible_notification_opt_in = true;
        let other_active = PushRegistrationHandoffIntentRecord::prepare(
            source.clone(),
            destination.clone(),
            &other_active,
            prepared_at + chrono::Duration::seconds(2),
        )
        .unwrap();
        assert!(matches!(
            apply_push_registration_desired_intent(&active_record, &other_active),
            Err(PersistenceError::Conflict(_))
        ));

        let late_active_receipt = receipt_for(
            &active,
            &source,
            &destination,
            prepared_at + chrono::Duration::seconds(2),
        );
        assert!(matches!(
            apply_verified_push_registration_receipt(
                &revoked_record,
                &active_record.request_digest,
                &late_active_receipt,
                prepared_at + chrono::Duration::seconds(3),
            ),
            Err(PersistenceError::Conflict(_))
        ));
    }
}
