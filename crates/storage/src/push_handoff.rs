use arkret_models_integration::{
    PushRegistrationHandoffRequestBody, PushRegistrationHandoffState, PushRegistrationId,
    PushRegistrationInstallationReceipt, PushRegistrationRecord,
};
use arkret_wire::{AccountId, DeviceId, DidCoreId, Hash};
use chrono::{DateTime, Utc};
use serde::Serialize;

use super::{PersistenceError, PersistenceResult, async_trait};

/// Local delivery state for one durable public Push Gateway desired intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PushRegistrationHandoffIntentStatus {
    AwaitingReceipt,
    ReceiptVerified,
}

/// Process-local continuation for the stable revoked-intent retry order.
///
/// The cursor is not a lease and carries no delivery authority. A worker may
/// discard it on restart and begin from the head; while alive it prevents a
/// permanently failing prefix from starving later Gateway destinations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PushRegistrationHandoffRetryCursor {
    pub updated_at: DateTime<Utc>,
    pub registration_id: PushRegistrationId,
}

/// Process-local continuation for the stable active-registration expiry order.
///
/// The cursor is deliberately not durable authority. It lets the bounded
/// worker move past an invalid or concurrently changed row, then wrap to the
/// head after reaching the end so the failed row remains observable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PushRegistrationHandoffExpiryCursor {
    pub created_at: DateTime<Utc>,
    pub registration_id: String,
}

/// Outcome of one bounded expiry sweep page.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PushRegistrationHandoffExpiryPage {
    pub scanned: usize,
    pub expired: Vec<PushRegistrationHandoffIntentRecord>,
    pub failed: usize,
    pub next_cursor: Option<PushRegistrationHandoffExpiryCursor>,
}

/// Station-private, grant-bound continuation for the one public hard logout.
/// The JWT itself is never stored. `revocation_ref` is accepted only for a
/// standard human grant bound to the trusted Account Authority browser session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PushHardLogoutJournalRecord {
    pub grant_token_digest: String,
    pub revocation_ref: String,
    pub account_id: AccountId,
    pub device_id: DeviceId,
    pub cnf_jkt: String,
    pub auth_side_confirmed: bool,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl PushRegistrationHandoffRetryCursor {
    #[must_use]
    pub fn after(record: &PushRegistrationHandoffIntentRecord) -> Self {
        Self {
            updated_at: record.updated_at,
            registration_id: record.registration_id.clone(),
        }
    }
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

/// Station-private coordinates for one client-visible push route.
///
/// These coordinates are storage metadata only. They MUST NOT be serialized
/// into the Gateway request body or receipt: the public Gateway learns the
/// pairwise target and device identity, never the owning account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PushRegistrationHandoffRouteLocator {
    pub account_id: AccountId,
    pub device_id: DeviceId,
    pub push_route_id: String,
    pub destination_gateway_id: DidCoreId,
}

impl PushRegistrationHandoffRouteLocator {
    pub fn validate_for(
        &self,
        source_station_id: &DidCoreId,
        request: &PushRegistrationHandoffRequestBody,
    ) -> PersistenceResult<()> {
        self.account_id
            .validate()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        if &self.account_id.station_id != source_station_id {
            return Err(PersistenceError::SchemaViolation(
                "push handoff local account does not belong to the source Station".to_owned(),
            ));
        }
        if self.push_route_id.trim().is_empty() {
            return Err(PersistenceError::SchemaViolation(
                "push handoff local route id must not be empty".to_owned(),
            ));
        }
        if &self.device_id != request.device_id() {
            return Err(PersistenceError::SchemaViolation(
                "push handoff local device differs from the Gateway request".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Exact desired state retained until a Gateway receipt has been verified and
/// committed. `canonical_request` is the body that must be replayed after a
/// timeout or process restart; callers must never regenerate a replacement
/// body for the same registration identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PushRegistrationHandoffIntentRecord {
    pub source_station_id: DidCoreId,
    pub local_route: PushRegistrationHandoffRouteLocator,
    /// Exact device authorization generation that created the active intent.
    /// This Station-private binding is retained across the terminal revoke so
    /// device cleanup can match one generation without consulting mutable
    /// inventory state.
    pub device_authorization: crate::DeviceRevocationGateSelector,
    /// Digest of the authenticated client desired input. Active intents bind
    /// the registration request before Station-generated identity metadata;
    /// revoked intents bind the exact unregister selector so an uncertain
    /// synchronous retry can recover only its own durable tombstones.
    pub client_input_digest: Hash,
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
        local_route: PushRegistrationHandoffRouteLocator,
        device_authorization: crate::DeviceRevocationGateSelector,
        client_input_digest: Hash,
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
        local_route.validate_for(&source_station_id, request)?;
        if device_authorization.principal_id != local_route.account_id.principal_id
            || device_authorization.station_id != source_station_id
            || device_authorization.device_id != local_route.device_id.as_str()
        {
            return Err(PersistenceError::SchemaViolation(
                "push handoff device authorization differs from its local route".to_owned(),
            ));
        }
        Ok(Self {
            source_station_id,
            destination_gateway_id: local_route.destination_gateway_id.clone(),
            local_route,
            device_authorization,
            client_input_digest,
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
        self.local_route
            .validate_for(&self.source_station_id, &request)?;
        if self.device_authorization.principal_id != self.local_route.account_id.principal_id
            || self.device_authorization.station_id != self.source_station_id
            || self.device_authorization.device_id != self.local_route.device_id.as_str()
        {
            return Err(PersistenceError::Internal(
                "stored push handoff device authorization binding mismatch".to_owned(),
            ));
        }
        if self.local_route.destination_gateway_id != self.destination_gateway_id {
            return Err(PersistenceError::Internal(
                "stored push handoff local route destination mismatch".to_owned(),
            ));
        }
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

    /// Re-check the Station-private route that will become current after a
    /// caller has verified the Gateway receipt signature. The handoff body is
    /// still the authority for every provider-route field; callers cannot
    /// substitute a different local registration after receipt verification.
    pub fn validate_active_local_registration(
        &self,
        authorization: &crate::DeviceRevocationGateSelector,
        registration: &PushRegistrationRecord,
    ) -> PersistenceResult<()> {
        self.validate()?;
        if registration.account_id != self.local_route.account_id
            || registration.device_id != self.local_route.device_id
            || registration.push_route_id != self.local_route.push_route_id
            || authorization.principal_id != registration.account_id.principal_id
            || authorization.station_id != registration.account_id.station_id
            || authorization.device_id != registration.device_id.as_str()
            || authorization != &self.device_authorization
            || !registration.retained_push_targets.is_empty()
        {
            return Err(PersistenceError::Conflict(
                "push registration differs from its local route or device authorization".to_owned(),
            ));
        }
        let request = self.request()?;
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
            return Err(PersistenceError::Conflict(
                "revoked push handoff cannot install a local active route".to_owned(),
            ));
        };
        if registration.registration_id.as_str() != registration_id.as_str()
            || registration.push_target_id != push_target_id
            || registration.device_id != device_id
            || registration.push_key != push_key
            || registration.platform != platform
            || registration.app_id != app_id
            || registration.visible_notification_opt_in != visible_notification_opt_in
            || registration.expires_at != expires_at
        {
            return Err(PersistenceError::Conflict(
                "local push registration differs from the verified Gateway request".to_owned(),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn same_desired_intent(&self, candidate: &Self) -> bool {
        self.source_station_id == candidate.source_station_id
            && self.local_route == candidate.local_route
            && self.device_authorization == candidate.device_authorization
            && self.client_input_digest == candidate.client_input_digest
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
        && stored.local_route == candidate.local_route
        && stored.device_authorization == candidate.device_authorization
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
#[allow(clippy::too_many_arguments)]
pub trait PushRegistrationHandoffStore: Send + Sync {
    async fn reserve_hard_logout_journal(
        &self,
        record: &PushHardLogoutJournalRecord,
    ) -> PersistenceResult<PushHardLogoutJournalRecord>;

    async fn hard_logout_journal(
        &self,
        grant_token_digest: &str,
    ) -> PersistenceResult<Option<PushHardLogoutJournalRecord>>;

    async fn pending_confirmed_hard_logouts(
        &self,
        after_digest: Option<&str>,
        limit: usize,
    ) -> PersistenceResult<Vec<PushHardLogoutJournalRecord>>;

    async fn mark_hard_logout_auth_confirmed(
        &self,
        grant_token_digest: &str,
    ) -> PersistenceResult<()>;

    async fn mark_hard_logout_completed(
        &self,
        grant_token_digest: &str,
        now: DateTime<Utc>,
    ) -> PersistenceResult<()>;

    async fn ensure_desired_intent(
        &self,
        source_station_id: &DidCoreId,
        local_route: &PushRegistrationHandoffRouteLocator,
        device_authorization: &crate::DeviceRevocationGateSelector,
        client_input_digest: &Hash,
        request: &PushRegistrationHandoffRequestBody,
        session_revocation_ref: Option<&str>,
        now: DateTime<Utc>,
    ) -> PersistenceResult<PushRegistrationHandoffIntentWrite>;

    async fn get_intent(
        &self,
        source_station_id: &DidCoreId,
        registration_id: &PushRegistrationId,
    ) -> PersistenceResult<Option<PushRegistrationHandoffIntentRecord>>;

    /// Return the outstanding intent for this exact Station-local route, or
    /// the most recently verified predecessor when no receipt is outstanding.
    /// This lookup never exposes the local locator on the Gateway wire.
    async fn lookup_local_route_intent(
        &self,
        source_station_id: &DidCoreId,
        local_route: &PushRegistrationHandoffRouteLocator,
    ) -> PersistenceResult<Option<PushRegistrationHandoffIntentRecord>>;

    async fn commit_verified_receipt(
        &self,
        source_station_id: &DidCoreId,
        registration_id: &PushRegistrationId,
        expected_request_digest: &Hash,
        receipt: &PushRegistrationInstallationReceipt,
        now: DateTime<Utc>,
    ) -> PersistenceResult<PushRegistrationHandoffReceiptWrite>;

    /// Atomically convert every exact current public handoff route and pending
    /// active intent matching this local client request into a durable terminal
    /// revoke intent, then remove the local delivery route. An exact retry
    /// returns its still-awaiting tombstones; zero matches and fully confirmed
    /// retries are idempotent.
    async fn begin_public_push_unregistration(
        &self,
        account_id: &AccountId,
        device_id: &DeviceId,
        push_key: Option<&str>,
        app_id: Option<&str>,
        now: DateTime<Utc>,
    ) -> PersistenceResult<Vec<PushRegistrationHandoffIntentRecord>>;

    /// Reconcile every active public route and pending active handoff for an
    /// account whose durable lifecycle is terminal. Each device transition
    /// uses the same exact tombstone UOW as client unregistration. A retry
    /// may return already-awaiting revokes; the receipt worker confirms them.
    async fn begin_public_push_account_deactivation(
        &self,
        account_id: &AccountId,
        now: DateTime<Utc>,
    ) -> PersistenceResult<usize>;

    /// Turn a bounded stable page of active public handoffs whose registration
    /// validity has ended (`expires_at <= now`) into terminal revoke intents,
    /// removing only each matching public local route. Candidates are isolated
    /// transactionally so one conflicting row cannot roll back the rest of the
    /// page. The returned cursor provides bounded cross-pass fairness.
    async fn expire_public_push_registrations(
        &self,
        source_station_id: &DidCoreId,
        now: DateTime<Utc>,
        after: Option<&PushRegistrationHandoffExpiryCursor>,
        limit: usize,
    ) -> PersistenceResult<PushRegistrationHandoffExpiryPage>;

    /// Stable, bounded retry view for the dedicated public-Gateway revoke
    /// worker. This is intentionally separate from the federation outbox.
    async fn list_awaiting_revoked_intents(
        &self,
        source_station_id: &DidCoreId,
        after: Option<&PushRegistrationHandoffRetryCursor>,
        limit: usize,
    ) -> PersistenceResult<Vec<PushRegistrationHandoffIntentRecord>>;

    /// Atomically commit a receipt whose detached JWS the caller has already
    /// verified and replace the exact Station-local push route it authorizes.
    /// The store re-checks all bindings and the live device gate, but does not
    /// resolve Gateway keys or perform signature verification itself.
    async fn commit_verified_active_receipt_and_push_route(
        &self,
        source_station_id: &DidCoreId,
        local_route: &PushRegistrationHandoffRouteLocator,
        registration_id: &PushRegistrationId,
        expected_request_digest: &Hash,
        receipt: &PushRegistrationInstallationReceipt,
        authorization: &crate::DeviceRevocationGateSelector,
        registration: &PushRegistrationRecord,
        session_revocation_ref: Option<&str>,
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

    fn local_route(
        source: &DidCoreId,
        destination: &DidCoreId,
        device_id: &DeviceId,
    ) -> PushRegistrationHandoffRouteLocator {
        PushRegistrationHandoffRouteLocator {
            account_id: AccountId::new(
                DidCoreId::new("ak:did_core:web:account.example").unwrap(),
                source.clone(),
            ),
            device_id: device_id.clone(),
            push_route_id: "com.example.app".to_owned(),
            destination_gateway_id: destination.clone(),
        }
    }

    fn client_input_digest(byte: char) -> Hash {
        Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn device_authorization(
        source: &DidCoreId,
        device_id: &DeviceId,
    ) -> crate::DeviceRevocationGateSelector {
        let event_id =
            arkret_wire::EventId::new("ak:event:AcIMom-0qqAXx_hmDJfxxaUJb_oJ64S3ARW1-WKFDCoD")
                .unwrap();
        crate::DeviceRevocationGateSelector {
            principal_id: DidCoreId::new("ak:did_core:web:account.example").unwrap(),
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
        let route = local_route(&source, &destination, active.device_id());
        let active_record = PushRegistrationHandoffIntentRecord::prepare(
            source.clone(),
            route.clone(),
            device_authorization(&source, active.device_id()),
            client_input_digest('1'),
            &active,
            now,
        )
        .unwrap();
        assert_eq!(
            active_record.desired_state,
            PushRegistrationHandoffState::Active
        );
        assert_eq!(active_record.request().unwrap(), active);
        assert!(
            !std::str::from_utf8(&active_record.canonical_request)
                .unwrap()
                .contains("account.example")
        );
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
        let revoked_record = PushRegistrationHandoffIntentRecord::prepare(
            source.clone(),
            route,
            device_authorization(&source, revoked.device_id()),
            client_input_digest('2'),
            &revoked,
            now,
        )
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
            local_route(&source, &destination, request.device_id()),
            device_authorization(&source, request.device_id()),
            client_input_digest('1'),
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
        let route = local_route(&source, &destination, active.device_id());
        let active_record = PushRegistrationHandoffIntentRecord::prepare(
            source.clone(),
            route.clone(),
            device_authorization(&source, active.device_id()),
            client_input_digest('1'),
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
            route.clone(),
            device_authorization(&source, revoked.device_id()),
            client_input_digest('2'),
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
            local_route(&source, &destination, wrong_device_revoke.device_id()),
            device_authorization(&source, wrong_device_revoke.device_id()),
            client_input_digest('2'),
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
            route,
            device_authorization(&source, other_active.device_id()),
            client_input_digest('3'),
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
