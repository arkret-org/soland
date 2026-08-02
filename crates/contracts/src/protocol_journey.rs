//! Canonical cross-service protocol-journey contracts.
//!
//! This module intentionally contains re-exports only.  Soland, Coauth and
//! Sodmin must share the SDK-owned closed wire types instead of cloning DTOs
//! or passing untyped JSON between services.

pub use arkret_models_collaboration::protocol_journey::{
    CausalIngressReceipt, ContactAcceptRequestBody, ContactOperationOutcome,
    ContactOperationRequestBody, ContactRejectRequestBody, ContactScopeUpdateRequestBody,
    ContactTombstoneRequestBody, DeploymentCeilingCompletenessCore, DeploymentCeilingCore,
    DeploymentCeilingForkRepair, DeploymentCeilingSignedHead, DirectConversationResolveOutcome,
    DirectConversationResolveRequestBody, HistoryShareContract, KeypackageTerminalCommand,
    ParticipationBits, ParticipationReplaceReceipt, ParticipationReplaceRelayRequestBody,
    ParticipationReplacementBatch, ParticipationScopeEvidenceChallenge,
    ParticipationScopeEvidencePrepareRequestBody, PeerContactSubmitOutcome,
    PeerContactSubmitRequestBody, SidecarEnsureOutcome, SidecarEnsureRequestBody,
};
pub use arkret_wire::{
    EventFederationSubmission, EventInitialSubmission, MembershipCompensationSubmissionEvidence,
};
