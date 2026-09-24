use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{PersistenceError, PersistenceResult};

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct DeviceRevocationGateSelector {
    pub principal_id: arkret_wire::DidCoreId,
    pub station_id: arkret_wire::DidCoreId,
    pub device_id: String,
    pub authorization_ref: arkret_wire::CommittedEventRef,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceRevocationGateAction {
    SessionGrantIssue,
    SessionGrantRefresh,
    DevicePairingCodeClaim,
    KeyPackageClaim,
    ToDeviceWrite,
    EventWrite,
}

impl DeviceRevocationGateAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SessionGrantIssue => "session_grant_issue",
            Self::SessionGrantRefresh => "session_grant_refresh",
            Self::DevicePairingCodeClaim => "device_pairing_code_claim",
            Self::KeyPackageClaim => "keypackage_claim",
            Self::ToDeviceWrite => "to_device_write",
            Self::EventWrite => "event_write",
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DeviceRevocationTransition {
    pub selector: DeviceRevocationGateSelector,
    pub revoke_ref: arkret_wire::CommittedEventRef,
    pub committed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum DeviceRevocationGateStatus {
    Active,
    Revoked {
        revoke_ref: arkret_wire::CommittedEventRef,
        committed_at: DateTime<Utc>,
    },
    AuthorityMismatch,
    GenerationMismatch,
}

impl DeviceRevocationGateStatus {
    pub fn ensure_allowed(&self) -> PersistenceResult<()> {
        match self {
            Self::Active => Ok(()),
            Self::Revoked { .. } => Err(PersistenceError::Conflict("device_revoked".to_owned())),
            Self::AuthorityMismatch | Self::GenerationMismatch => Err(PersistenceError::Conflict(
                "failed_precondition: device gate selector mismatch".to_owned(),
            )),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DeviceRevocationTargetRecord {
    pub selector: DeviceRevocationGateSelector,
    pub revoke_ref: arkret_wire::CommittedEventRef,
    pub committed_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceRevocationTransitionDecision {
    Insert,
    Duplicate,
}

pub fn classify_device_revocation_transition(
    transition: &DeviceRevocationTransition,
    existing: Option<&DeviceRevocationTargetRecord>,
) -> PersistenceResult<DeviceRevocationTransitionDecision> {
    match existing {
        None => Ok(DeviceRevocationTransitionDecision::Insert),
        Some(existing)
            if existing.selector == transition.selector
                && existing.revoke_ref == transition.revoke_ref =>
        {
            Ok(DeviceRevocationTransitionDecision::Duplicate)
        }
        Some(_) => Err(PersistenceError::Conflict(
            "duplicate_conflict: device revocation target differs".to_owned(),
        )),
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeviceRevocationGateLinearizationRequest {
    pub principal_id: arkret_wire::DidCoreId,
    pub station_id: arkret_wire::DidCoreId,
    pub device_id: String,
    pub expected_authorization_ref: Option<arkret_wire::CommittedEventRef>,
    /// Receiver-derived current binding; never populated from peer bytes.
    pub origin_current_selector: Option<DeviceRevocationGateSelector>,
    pub action_class: DeviceRevocationGateAction,
    pub intent_digest: String,
    pub requested_at: DateTime<Utc>,
}

#[must_use]
pub fn selector_comparison_status(
    request: &DeviceRevocationGateLinearizationRequest,
    current: Option<&DeviceRevocationGateSelector>,
) -> Option<DeviceRevocationGateStatus> {
    let Some(current) = current else {
        return Some(DeviceRevocationGateStatus::AuthorityMismatch);
    };
    if request.principal_id != current.principal_id
        || request.station_id != current.station_id
        || request.device_id != current.device_id
    {
        return Some(DeviceRevocationGateStatus::AuthorityMismatch);
    }
    if request.expected_authorization_ref.as_ref() != Some(&current.authorization_ref) {
        return Some(DeviceRevocationGateStatus::GenerationMismatch);
    }
    None
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeviceRevocationGateLinearization {
    pub request: DeviceRevocationGateLinearizationRequest,
    pub status: DeviceRevocationGateStatus,
    pub linearization_seq: u64,
    pub linearized_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeviceRevocationCleanupIntent {
    pub revoke_ref: arkret_wire::CommittedEventRef,
    pub selector: DeviceRevocationGateSelector,
    pub created_at: DateTime<Utc>,
    pub material_cleanup_completed_at: Option<DateTime<Utc>>,
    pub mls_obligation_completed_at: Option<DateTime<Utc>>,
}

/// Human-device admission state folded from one confirmed PCR cut: the
/// accepted `device_authorization`, `device_generation`, revoke proposals and
/// the verified conflict index, all read under the same snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PcrDeviceAdmission {
    Active,
    Revoked,
    RevocationPending,
    /// The authorization generation is no longer current or is conflicted.
    GenerationFenced,
    /// The instant lies outside the accepted authorization window.
    OutsideAuthorizationWindow,
}

impl PcrDeviceAdmission {
    /// Registered code refusing a producer in this state; `None` when active.
    #[must_use]
    pub const fn refusal_code(self) -> Option<crate::ConflictCode> {
        match self {
            Self::Active => None,
            Self::Revoked => Some(crate::ConflictCode::DeviceRevoked),
            Self::RevocationPending => Some(crate::ConflictCode::DeviceRevocationPending),
            Self::GenerationFenced => Some(crate::ConflictCode::DeviceGenerationFenced),
            Self::OutsideAuthorizationWindow => Some(crate::ConflictCode::DeviceUnauthorized),
        }
    }
}

#[async_trait]
pub trait DeviceRevocationStore: Send + Sync {
    /// Authoritative PCR human-device admission at `now`. Missing or
    /// incomplete typed current is an error, never an implicit active device.
    async fn pcr_device_admission(
        &self,
        _account: &arkret_wire::AccountId,
        _device_id: &arkret_wire::DeviceId,
        _now: DateTime<Utc>,
    ) -> PersistenceResult<PcrDeviceAdmission> {
        Err(PersistenceError::SchemaViolation(
            "PCR device status provider is unavailable".to_owned(),
        ))
    }

    async fn gate_status(
        &self,
        selector: &DeviceRevocationGateSelector,
    ) -> PersistenceResult<DeviceRevocationGateStatus>;

    async fn list_targets(
        &self,
        selector: &DeviceRevocationGateSelector,
    ) -> PersistenceResult<Vec<DeviceRevocationTargetRecord>>;

    async fn target_for_event(
        &self,
        event_id: &arkret_wire::EventId,
    ) -> PersistenceResult<Option<DeviceRevocationTargetRecord>>;

    async fn linearize_gate(
        &self,
        request: DeviceRevocationGateLinearizationRequest,
    ) -> PersistenceResult<DeviceRevocationGateLinearization>;

    /// Installs the revocation projection only after the authority's commit is
    /// durable. Exact retries are idempotent.
    async fn commit_revocation(
        &self,
        transition: &DeviceRevocationTransition,
    ) -> PersistenceResult<DeviceRevocationTransitionDecision>;

    async fn pending_cleanup_intents(
        &self,
        limit: usize,
    ) -> PersistenceResult<Vec<DeviceRevocationCleanupIntent>>;

    async fn complete_material_cleanup(
        &self,
        event_id: &arkret_wire::EventId,
        completed_at: DateTime<Utc>,
    ) -> PersistenceResult<bool>;

    async fn complete_mls_obligation(
        &self,
        event_id: &arkret_wire::EventId,
        completed_at: DateTime<Utc>,
    ) -> PersistenceResult<bool>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_current_selector_fails_closed() {
        let request = DeviceRevocationGateLinearizationRequest {
            principal_id: arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            station_id: arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            device_id: "device-a".to_owned(),
            expected_authorization_ref: None,
            origin_current_selector: None,
            action_class: DeviceRevocationGateAction::EventWrite,
            intent_digest: "sha256:test".to_owned(),
            requested_at: Utc::now(),
        };
        assert_eq!(
            selector_comparison_status(&request, None),
            Some(DeviceRevocationGateStatus::AuthorityMismatch)
        );
    }

    #[test]
    fn device_pairing_code_claim_has_a_distinct_durable_action() {
        assert_eq!(
            DeviceRevocationGateAction::DevicePairingCodeClaim.as_str(),
            "device_pairing_code_claim"
        );
        assert_ne!(
            DeviceRevocationGateAction::DevicePairingCodeClaim,
            DeviceRevocationGateAction::EventWrite
        );
    }
}
