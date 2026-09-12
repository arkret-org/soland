use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{PersistenceError, PersistenceResult};

pub const MAX_DEVICE_REVOCATION_PROPOSALS_PER_GENERATION: usize = 128;

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct DeviceRevocationGateSelector {
    pub principal_id: arkret_identifiers::DidCoreId,
    pub station_id: arkret_identifiers::DidCoreId,
    pub device_id: String,
    pub target_device_authorize_event_id: String,
    pub target_device_generation_ref: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceRevocationGateAction {
    SessionGrantIssue,
    SessionGrantRefresh,
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
            Self::KeyPackageClaim => "keypackage_claim",
            Self::ToDeviceWrite => "to_device_write",
            Self::EventWrite => "event_write",
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DeviceRevocationTransition {
    pub selector: DeviceRevocationGateSelector,
    pub proposal_event_id: String,
    pub proposal_digest: String,
    pub control_proposal_ack: arkret_wire::ControlProposalAck,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum DeviceRevocationTargetStatus {
    Pending {
        decisions: Vec<arkret_wire::ControlProposalDecision>,
        decision_overdue: bool,
    },
    Rejected {
        deciding_seal_id: arkret_identifiers::SealId,
    },
    Revoked {
        covering_seal_id: String,
        sealed_at: DateTime<Utc>,
    },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DeviceRevocationTargetRecord {
    pub selector: DeviceRevocationGateSelector,
    pub proposal_event_id: String,
    pub proposal_digest: String,
    pub accepted_at: DateTime<Utc>,
    pub acceptance_seq: u64,
    pub control_proposal_ack: arkret_wire::ControlProposalAck,
    pub status: DeviceRevocationTargetStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceRevocationTransitionDecision {
    Insert,
    Duplicate,
}

pub enum DeviceRevocationTransitionSnapshot<'a> {
    Existing {
        selector: &'a DeviceRevocationGateSelector,
        proposal_event_id: &'a str,
        control_proposal_ack: &'a arkret_wire::ControlProposalAck,
    },
    New {
        gate_status: &'a DeviceRevocationGateStatus,
        live_proposal_count: usize,
    },
}

/// Classify one accepted device-revocation target independently of adapter
/// locking and sequence allocation.
pub fn classify_device_revocation_transition(
    transition: &DeviceRevocationTransition,
    snapshot: DeviceRevocationTransitionSnapshot<'_>,
) -> PersistenceResult<DeviceRevocationTransitionDecision> {
    match snapshot {
        DeviceRevocationTransitionSnapshot::Existing {
            selector,
            proposal_event_id,
            control_proposal_ack,
        } => {
            if selector == &transition.selector
                && proposal_event_id == transition.proposal_event_id
                && control_proposal_ack == &transition.control_proposal_ack
            {
                Ok(DeviceRevocationTransitionDecision::Duplicate)
            } else {
                Err(PersistenceError::Conflict(
                    "duplicate_conflict: device revocation target differs".to_owned(),
                ))
            }
        }
        DeviceRevocationTransitionSnapshot::New {
            gate_status,
            live_proposal_count,
        } => {
            if matches!(gate_status, DeviceRevocationGateStatus::Revoked { .. }) {
                return Err(PersistenceError::Conflict("device_revoked".to_owned()));
            }
            if live_proposal_count >= MAX_DEVICE_REVOCATION_PROPOSALS_PER_GENERATION {
                return Err(PersistenceError::Conflict(
                    "schema_violation: device revocation proposal cap exceeded".to_owned(),
                ));
            }
            Ok(DeviceRevocationTransitionDecision::Insert)
        }
    }
}

#[cfg(test)]
mod transition_tests {
    use super::*;

    fn selector(device_id: &str) -> DeviceRevocationGateSelector {
        DeviceRevocationGateSelector {
            principal_id: arkret_identifiers::DidCoreId::new(
                "ak:did_core:web:principal.example".to_owned(),
            )
            .unwrap(),
            station_id: arkret_identifiers::DidCoreId::new(
                "ak:did_core:web:soland.example".to_owned(),
            )
            .unwrap(),
            device_id: device_id.to_owned(),
            target_device_authorize_event_id: "authorize-event".to_owned(),
            target_device_generation_ref: 1,
        }
    }

    fn ack() -> arkret_wire::ControlProposalAck {
        let created_at = Utc::now();
        let policy = arkret_wire::ControlProposalDecisionPolicy::default();
        let mut authority_ack = arkret_wire::ControlProposalAck {
            kind: arkret_wire::ControlProposalAckKind::SignedAck,
            defer_count: 0,
            realm_id: arkret_wire::RealmId::new(
                "ak:realm:AYcO0aKZZvKELI-s58wUjRHsrz5v8Y51T0_sGUTciDVw".to_owned(),
            )
            .unwrap(),
            proposal_digest: arkret_wire::Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap(),
            received_at: created_at,
            decision_due_at: created_at + policy.decision_window,
            absolute_due_at: created_at + policy.absolute_horizon,
            authority_set_ref: arkret_wire::Hash::new(format!("sha256:{}", "a".repeat(64)))
                .unwrap(),
            signature: arkret_wire::PayloadSignature {
                verification_method: arkret_wire::DidUrl::new(
                    "did:web:soland.example#authority-1".to_owned(),
                )
                .unwrap(),
                payload_digest: arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64)))
                    .unwrap(),
                created_at,
                jws: "e30..c2ln".to_owned(),
            },
        };
        authority_ack.signature.payload_digest = authority_ack.ack_body_digest().unwrap();
        authority_ack
    }

    fn transition() -> DeviceRevocationTransition {
        DeviceRevocationTransition {
            selector: selector("device-a"),
            proposal_event_id: "proposal-event".to_owned(),
            proposal_digest: format!("sha256:{}", "b".repeat(64)),
            control_proposal_ack: ack(),
        }
    }

    #[test]
    fn exact_replay_is_duplicate_but_selector_drift_conflicts() {
        let transition = transition();
        assert_eq!(
            classify_device_revocation_transition(
                &transition,
                DeviceRevocationTransitionSnapshot::Existing {
                    selector: &transition.selector,
                    proposal_event_id: &transition.proposal_event_id,
                    control_proposal_ack: &transition.control_proposal_ack,
                },
            )
            .unwrap(),
            DeviceRevocationTransitionDecision::Duplicate
        );
        assert!(
            classify_device_revocation_transition(
                &transition,
                DeviceRevocationTransitionSnapshot::Existing {
                    selector: &selector("device-b"),
                    proposal_event_id: &transition.proposal_event_id,
                    control_proposal_ack: &transition.control_proposal_ack,
                },
            )
            .is_err()
        );
    }

    #[test]
    fn new_target_respects_terminal_gate_and_live_cap() {
        let transition = transition();
        assert_eq!(
            classify_device_revocation_transition(
                &transition,
                DeviceRevocationTransitionSnapshot::New {
                    gate_status: &DeviceRevocationGateStatus::Active,
                    live_proposal_count: 0,
                },
            )
            .unwrap(),
            DeviceRevocationTransitionDecision::Insert
        );
        assert!(
            classify_device_revocation_transition(
                &transition,
                DeviceRevocationTransitionSnapshot::New {
                    gate_status: &DeviceRevocationGateStatus::Revoked {
                        covering_seal_id: "seal".to_owned(),
                    },
                    live_proposal_count: 0,
                },
            )
            .is_err()
        );
        assert!(
            classify_device_revocation_transition(
                &transition,
                DeviceRevocationTransitionSnapshot::New {
                    gate_status: &DeviceRevocationGateStatus::Active,
                    live_proposal_count: MAX_DEVICE_REVOCATION_PROPOSALS_PER_GENERATION,
                },
            )
            .is_err()
        );
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum DeviceRevocationGateStatus {
    Active,
    Pending { blocking_proposal_digest: String },
    Revoked { covering_seal_id: String },
    AuthorityMismatch,
    GenerationMismatch,
}

impl DeviceRevocationGateStatus {
    pub fn ensure_allowed(&self) -> PersistenceResult<()> {
        match self {
            Self::Active => Ok(()),
            Self::Pending { .. } => Err(PersistenceError::Conflict(
                "device_revocation_pending".to_owned(),
            )),
            Self::Revoked { .. } => Err(PersistenceError::Conflict("device_revoked".to_owned())),
            Self::AuthorityMismatch | Self::GenerationMismatch => Err(PersistenceError::Conflict(
                "failed_precondition: device gate selector mismatch".to_owned(),
            )),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeviceRevocationGateLinearizationRequest {
    pub principal_id: arkret_identifiers::DidCoreId,
    pub station_id: arkret_identifiers::DidCoreId,
    pub device_id: String,
    pub expected_device_authorize_event_id: Option<String>,
    pub expected_device_generation_ref: Option<u64>,
    /// Receiver-derived current binding; never populated from peer wire bytes.
    /// Keeping it in the storage command makes the final mismatch decision an
    /// immutable replayable fact rather than a pre-query hint.
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
    match (
        request.expected_device_authorize_event_id.as_deref(),
        request.expected_device_generation_ref,
    ) {
        (Some(event_id), Some(generation))
            if event_id != current.target_device_authorize_event_id
                || generation != current.target_device_generation_ref =>
        {
            return Some(DeviceRevocationGateStatus::GenerationMismatch);
        }
        (Some(_), Some(_)) | (None, None) => {}
        _ => return Some(DeviceRevocationGateStatus::GenerationMismatch),
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
    pub proposal_digest: String,
    pub proposal_event_id: String,
    pub selector: DeviceRevocationGateSelector,
    pub covering_seal_id: String,
    pub created_at: DateTime<Utc>,
    pub material_cleanup_completed_at: Option<DateTime<Utc>>,
    pub mls_obligation_completed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlProposalDecisionCommitOutcome {
    Accepted,
    Duplicate,
}

#[async_trait]
pub trait DeviceRevocationStore: Send + Sync {
    /// Attach the exact generic Control Event store used by the projection
    /// service. Durable adapters derive their view from the generic row and
    /// ignore this hook; the memory adapter uses it to commit both views while
    /// holding one process-local decision lock.
    fn bind_control_event_store(
        &self,
        _control_events: Arc<dyn arkret_state::state::ControlEventStore>,
    ) {
    }

    async fn gate_status(
        &self,
        selector: &DeviceRevocationGateSelector,
    ) -> PersistenceResult<DeviceRevocationGateStatus>;

    async fn list_targets(
        &self,
        selector: &DeviceRevocationGateSelector,
    ) -> PersistenceResult<Vec<DeviceRevocationTargetRecord>>;

    /// Resolve the immutable reducer-derived target, never the current device
    /// generation, when projecting a historical or pending proposal.
    async fn target_for_proposal(
        &self,
        proposal_digest: &str,
    ) -> PersistenceResult<Option<DeviceRevocationTargetRecord>>;

    /// Atomically order an immutable action intent against revoke acceptance.
    /// Exact replay returns the first durable linearization unchanged.
    async fn linearize_gate(
        &self,
        request: DeviceRevocationGateLinearizationRequest,
    ) -> PersistenceResult<DeviceRevocationGateLinearization>;

    /// Atomically append a verified decision and update the typed revoke view.
    /// PostgreSQL updates the generic row in one transaction and derives the
    /// target view by join. The memory adapter updates its generic and typed
    /// views while holding one shared lock. The operation also handles generic
    /// non-revoke Control Events so exact replay has one CAS result surface.
    async fn commit_decision(
        &self,
        proposal_digest: &str,
        decision: &arkret_wire::ControlProposalDecision,
        policy: arkret_wire::ControlProposalDecisionPolicy,
    ) -> PersistenceResult<ControlProposalDecisionCommitOutcome>;

    async fn mark_sealed(
        &self,
        proposal_digest: &str,
        covering_seal_id: &str,
        sealed_at: DateTime<Utc>,
    ) -> PersistenceResult<bool>;

    async fn pending_cleanup_intents(
        &self,
        limit: usize,
    ) -> PersistenceResult<Vec<DeviceRevocationCleanupIntent>>;

    /// Mark only durable device-generation material cleanup complete. This
    /// must not acknowledge an in-memory MLS removal enqueue.
    async fn complete_material_cleanup(
        &self,
        proposal_digest: &str,
        completed_at: DateTime<Utc>,
    ) -> PersistenceResult<bool>;

    /// Acknowledge the MLS removal step only after its durable obligation or
    /// covering MLS commit is observable. Until then restart recovery keeps
    /// returning the sealed cleanup intent for idempotent reconstruction.
    async fn complete_mls_obligation(
        &self,
        proposal_digest: &str,
        completed_at: DateTime<Utc>,
    ) -> PersistenceResult<bool>;

    /// Complete the MLS step using the exact revoke Event id carried in an
    /// MLS removal obligation's `membership_frontier`. Implementations must
    /// reject an ambiguous match rather than choosing a proposal digest.
    async fn complete_mls_obligation_by_event_id(
        &self,
        proposal_event_id: &str,
        completed_at: DateTime<Utc>,
    ) -> PersistenceResult<bool>;
}
