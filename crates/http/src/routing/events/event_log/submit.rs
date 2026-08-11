use std::collections::{BTreeMap, BTreeSet};
use std::hash::Hasher;
use std::sync::{Arc, OnceLock};

use arkret_event_draft::EventPayloadExt as _;
use arkret_models_collaboration::event_sync::EventsSubmitFederationRequestBody;
use arkret_models_collaboration::http_bodies::EventsSubmitRejectedItem;
use arkret_wire::ReasonCode;
use ed25519_dalek::Signer as _;

use super::*;
use crate::invite_claim_proofs::{
    invite_claim_proof_context_from_projection, verify_invite_claim_proofs_for_operation,
};

/// SOL-SEC-03 — per-Realm-actor submit serialization uses a fixed-size pool of
/// locks keyed by a hash of `(realm_id, actor_id)`, instead of an unbounded
/// `HashMap` entry that was never evicted. Federation inbound can carry
/// arbitrarily many distinct actor DIDs, so a per-actor map grows without bound
/// (memory DoS). A fixed pool bounds memory to `ACTOR_SUBMIT_LOCK_SHARDS`
/// entries; two actors hashing to the same shard merely serialize together,
/// which is a safe superset of the required per-actor exclusion.
const ACTOR_SUBMIT_LOCK_SHARDS: usize = 1024;
const ACCOUNT_DATA_SUBMIT_LOCK_SHARDS: usize = 1024;
const INVITE_LIFECYCLE_LOCK_SHARDS: usize = 1024;
pub(super) const IDEMPOTENCY_KEY_TTL_SECONDS: i64 = 86_400;

static ACTOR_SUBMIT_LOCKS: OnceLock<Vec<Arc<tokio::sync::Mutex<()>>>> = OnceLock::new();
static ACCOUNT_DATA_SUBMIT_LOCKS: OnceLock<Vec<Arc<tokio::sync::Mutex<()>>>> = OnceLock::new();
static INVITE_LIFECYCLE_LOCKS: OnceLock<Vec<Arc<tokio::sync::Mutex<()>>>> = OnceLock::new();
static SERVICE_EVENT_AUTHORING_LOCK: OnceLock<Arc<tokio::sync::Mutex<()>>> = OnceLock::new();

mod identity_anchor;
use identity_anchor::{
    PcrGenesisPins, batch_contains_identity_anchor, submit_identity_anchor_batch,
};
mod ghost_provision;
pub(in crate::routing) use ghost_provision::submit_ghost_provision_batch;
mod sidecar_ensure;
pub(crate) use sidecar_ensure::submit_sidecar_ensure_batch;
mod realm_bootstrap;
use realm_bootstrap::{batch_begins_realm_create, submit_realm_bootstrap_batch};

fn rejected_item(
    id: String,
    reason_code: ReasonCode,
    detail: Option<String>,
) -> EventsSubmitRejectedItem {
    EventsSubmitRejectedItem {
        index: None,
        id,
        reason_code,
        detail,
        missing_event_ids: Vec::new(),
        missing_seal_refs: Vec::new(),
        missing_event_digests: Vec::new(),
    }
}

fn actor_submit_lock(realm_id: &str, actor_id: &str) -> Arc<tokio::sync::Mutex<()>> {
    let locks = ACTOR_SUBMIT_LOCKS.get_or_init(|| {
        (0..ACTOR_SUBMIT_LOCK_SHARDS)
            .map(|_| Arc::new(tokio::sync::Mutex::new(())))
            .collect()
    });
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    std::hash::Hash::hash(realm_id, &mut hasher);
    std::hash::Hash::hash(actor_id, &mut hasher);
    let shard = (hasher.finish() as usize) % ACTOR_SUBMIT_LOCK_SHARDS;
    locks[shard].clone()
}

fn account_data_submit_lock(owner: &str, key: &str) -> Arc<tokio::sync::Mutex<()>> {
    let locks = ACCOUNT_DATA_SUBMIT_LOCKS.get_or_init(|| {
        (0..ACCOUNT_DATA_SUBMIT_LOCK_SHARDS)
            .map(|_| Arc::new(tokio::sync::Mutex::new(())))
            .collect()
    });
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    std::hash::Hash::hash(owner, &mut hasher);
    std::hash::Hash::hash(key, &mut hasher);
    let shard = (hasher.finish() as usize) % ACCOUNT_DATA_SUBMIT_LOCK_SHARDS;
    locks[shard].clone()
}

fn invite_lifecycle_submit_lock(
    realm_id: &str,
    envelope: &Value,
) -> Option<Arc<tokio::sync::Mutex<()>>> {
    let invite_id = envelope
        .get("payload")
        .and_then(Value::as_object)
        .and_then(|payload| {
            payload
                .get("invite_id")
                .or_else(|| payload.get("invite_ref"))
                .or_else(|| payload.get("invite").and_then(|invite| invite.get("id")))
        })
        .and_then(Value::as_str)?;
    let locks = INVITE_LIFECYCLE_LOCKS.get_or_init(|| {
        (0..INVITE_LIFECYCLE_LOCK_SHARDS)
            .map(|_| Arc::new(tokio::sync::Mutex::new(())))
            .collect()
    });
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    std::hash::Hash::hash(realm_id, &mut hasher);
    std::hash::Hash::hash(invite_id, &mut hasher);
    let shard = (hasher.finish() as usize) % INVITE_LIFECYCLE_LOCK_SHARDS;
    Some(locks[shard].clone())
}

pub(in crate::routing) fn service_event_authoring_lock() -> Arc<tokio::sync::Mutex<()>> {
    SERVICE_EVENT_AUTHORING_LOCK
        .get_or_init(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

fn stamp_projection_operation_received_at(
    operation: &mut arkret_event_draft::ProjectedEventOperation,
    received_at: chrono::DateTime<chrono::Utc>,
) {
    if !matches!(
        &operation.event_kind,
        arkret_wire::EventKind::MemberState | arkret_wire::EventKind::CircleMemberState
    ) {
        return;
    }
    let Some(payload) = operation.payload.as_object_mut() else {
        return;
    };
    payload.insert(
        "event_received_at".to_owned(),
        Value::String(arkret_canonical::format_timestamp_canonical(received_at)),
    );
}

fn batch_is_managed_agent_pcr_create(envelopes: &[Value]) -> bool {
    if envelopes.len() != 1 {
        return false;
    }
    let Ok(event) = serde_json::from_value::<arkret_wire::Event>(envelopes[0].clone()) else {
        return false;
    };
    event.kind == arkret_wire::EventKind::RealmCreate
        && event.executed_by.as_ref() != Some(&event.actor_id)
        && arkret_bootstrap::materialize_managed_agent_pcr_control(
            std::slice::from_ref(&event),
            &genesis_cell_write_projector,
        )
        .is_ok()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::routing) enum DataEventQueryGrade {
    Observed,
    Stale,
}

#[derive(Debug)]
pub(in crate::routing) struct ValidatedEventEnvelope {
    pub(in crate::routing) event_id: String,
    pub(in crate::routing) actor_id: String,
    pub(in crate::routing) device_id: String,
    pub(in crate::routing) actor_seq: u64,
    pub(in crate::routing) realm_id: String,
    pub(in crate::routing) kind: String,
    pub(in crate::routing) schema_id: String,
    pub(in crate::routing) prev_refs: Vec<String>,
    pub(in crate::routing) authorized_refs: Vec<String>,
    pub(in crate::routing) canonical_digest: String,
    pub(in crate::routing) canonical_bytes: Vec<u8>,
    pub(in crate::routing) data_event_query_grade: DataEventQueryGrade,
}

#[derive(Debug)]
pub(in crate::routing) struct EventValidationError {
    pub(in crate::routing) status: StatusCode,
    pub(in crate::routing) code: &'static str,
    pub(in crate::routing) message: String,
    pub(in crate::routing) reason_code: Option<&'static str>,
}

#[derive(Debug)]
pub(in crate::routing) struct SubmitOneError {
    pub status: StatusCode,
    pub code: String,
    pub message: String,
    pub details: Option<Value>,
    pub quarantine_event_id: Option<String>,
}

#[derive(Debug)]
pub(in crate::routing) struct SubmittedEventOutcome {
    pub event_id: String,
    pub duplicate: bool,
    pub outcome: EventsSubmitOutcome,
}

#[derive(Debug)]
pub(in crate::routing) struct EventCommitIdempotency {
    pub principal_id: String,
    pub key: String,
    pub service_id: String,
    pub request_hash: String,
}

/// Persist a collision only after the shared envelope validator has rebound the
/// carried EventId to the digest-covered canonical preimage.  Calling the
/// storage port is intentional: it atomically moves the previously accepted
/// variant and this verified variant into the durable quarantine bucket.
pub(super) async fn quarantine_verified_event_collision(
    state: &AppState,
    record: CanonicalEventRecord,
) -> SubmitOneError {
    let event_id = record.event_id.clone();
    match state.event_queries().store_canonical_event(record).await {
        Err(error) if error.is_conflict("event_hash_collision") => SubmitOneError::quarantine(
            event_id,
            "witness_disagreement",
            "verified Event variants disagree for the same full EventId",
        ),
        Err(error) => SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            format!("durable Event collision quarantine failed: {error}"),
        ),
        Ok(()) => SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "collision admission unexpectedly accepted a second canonical preimage",
        ),
    }
}

pub(super) fn map_event_hash_collision(
    event_id: impl Into<String>,
    error: &soland_services::ServiceError,
) -> Option<SubmitOneError> {
    error.is_conflict("event_hash_collision").then(|| {
        SubmitOneError::quarantine(
            event_id,
            "witness_disagreement",
            "verified Event variants disagree for the same full EventId",
        )
    })
}

#[cfg(test)]
mod event_collision_reason_tests {
    use super::*;

    #[test]
    fn storage_collision_maps_to_registered_witness_disagreement_reason() {
        let error = map_event_hash_collision(
            "ak:event:fixture",
            &soland_services::ServiceError::Conflict("event_hash_collision".to_owned()),
        )
        .expect("storage collision must be externally quarantined");

        assert_eq!(error.code, "witness_disagreement");
        assert_eq!(
            error.quarantine_event_id.as_deref(),
            Some("ak:event:fixture")
        );
    }
}

#[derive(Debug, Clone)]
pub(in crate::routing) struct RealmBootstrapBatchContext {
    pub(in crate::routing) realm_id: String,
    pub(in crate::routing) actor_id: String,
    /// Digest suite staged by the leading Realm-create Event.
    ///
    /// Follow-up Events in an atomic bootstrap unit are validated before the
    /// Realm projection exists, so their content-bound identities must resolve
    /// the suite from the same signed unit rather than from durable state.
    pub(in crate::routing) digest_algorithm: Option<String>,
    pub(in crate::routing) identity_anchor_event_id: Option<String>,
    pub(in crate::routing) self_principal_pcr_bootstrap: bool,
    /// Typed SDK payload for the candidate device in the second slot of a
    /// registration-anchor or PCR-recovery unit.  Admission parses the wire
    /// Event exactly once at the boundary and carries this DTO through proof
    /// validation; downstream code must not rediscover security fields by
    /// walking `serde_json::Value`.
    pub(in crate::routing) identity_anchor_candidate_device: Option<
        arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload,
    >,
    /// Resolution commitment that defines the DID URL base for the candidate
    /// device Event proof.  For genesis this is the exact typed
    /// `RealmCreatePayload.object.initial_resolution`; recovery may load the
    /// same public SDK DTO from the accepted PCR resolution projection.
    pub(in crate::routing) identity_anchor_resolution:
        Option<arkret_models_identity::ResolutionCommitment>,
    /// This batch already passed the closed three-Event Direct Conversation
    /// founding-plan validator, so its member/Strand follow-ups may be
    /// admitted before the new Realm has a durable membership projection.
    pub(in crate::routing) direct_conversation_founding: bool,
    /// The genesis authority-root value this unit's `ak.realm.create` derives.
    ///
    /// Present only for an ordinary Realm genesis unit: it is the staged root
    /// proof a follow-up Event cites through
    /// `ak:cell:ak.component.realm.authority_root.v1:null` while no accepted
    /// Seal covers the cell yet (`realm-and-space.md` section 2.5).
    pub(in crate::routing) authority_root:
        Option<arkret_policy::realm_bootstrap::RealmAuthorityRootValue>,
}

pub(in crate::routing::events::event_log) fn staged_realm_digest_algorithm(
    envelope: &Value,
) -> String {
    envelope
        .get("payload")
        .and_then(|payload| {
            payload
                .get("object")
                .and_then(|object| object.get("digest_algorithm"))
                .or_else(|| payload.get("digest_algorithm"))
        })
        .and_then(Value::as_str)
        .unwrap_or("sha256")
        .to_owned()
}

/// Closed authorization context for trusted internal protocol adapters. This
/// does not skip schema, proof, actor-lock, idempotency or reducer admission;
/// it only supplies the protocol-specific substitute for ordinary Realm
/// membership (and, for the exact applet-provisioning Event, delegated-grant
/// lookup) after the adapter has verified its durable binding.
#[derive(Debug, Clone)]
pub(in crate::routing) struct InternalEventAdmission {
    realm_id: String,
    actor_id: String,
    session_actor_id: String,
    kind: String,
    device_id: String,
    binding: InternalEventBinding,
}

#[derive(Debug, Clone)]
pub(in crate::routing) struct VerifiedFederatedAgentSignerEvidence {
    agent_id: arkret_wire::DidCoreId,
    verification_method: arkret_wire::DidUrl,
    public_key: [u8; 32],
}

impl VerifiedFederatedAgentSignerEvidence {
    pub(in crate::routing::events::event_log) fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }
}

#[derive(Debug, Clone)]
enum InternalEventBinding {
    MimiProvider {
        binding_ref: String,
    },
    AccountData {
        owner: String,
        key: String,
    },
    MimiModerationReport {
        reporter: String,
        target_ref: String,
    },
    AppletFormal {
        event_id: String,
    },
    SidecarEnsure {
        event_id: String,
    },
    PeerFederatedEvent {
        event_id: String,
        signer_key_evidence: Vec<arkret_wire::event_envelope::FederatedDeviceSigningKeyEvidence>,
        agent_signer_evidence: Vec<VerifiedFederatedAgentSignerEvidence>,
    },
}

impl InternalEventAdmission {
    pub(in crate::routing) fn mimi_provider(
        realm_id: impl Into<String>,
        actor_id: impl Into<String>,
        binding_ref: impl Into<String>,
    ) -> Self {
        let actor_id = actor_id.into();
        Self {
            realm_id: realm_id.into(),
            session_actor_id: actor_id.clone(),
            actor_id,
            kind: arkret_wire::EventKind::MessageCreate.as_str().to_owned(),
            device_id: "mimi-provider-facade".to_owned(),
            binding: InternalEventBinding::MimiProvider {
                binding_ref: binding_ref.into(),
            },
        }
    }

    pub(in crate::routing) fn account_data(
        realm_id: impl Into<String>,
        actor_id: impl Into<String>,
        device_id: impl Into<String>,
        owner: impl Into<String>,
        key: impl Into<String>,
    ) -> Self {
        let actor_id = actor_id.into();
        Self {
            realm_id: realm_id.into(),
            session_actor_id: actor_id.clone(),
            actor_id,
            kind: arkret_wire::EventKind::AccountDataSet.as_str().to_owned(),
            device_id: device_id.into(),
            binding: InternalEventBinding::AccountData {
                owner: owner.into(),
                key: key.into(),
            },
        }
    }

    pub(in crate::routing) fn mimi_moderation_report(
        realm_id: impl Into<String>,
        actor_id: impl Into<String>,
        reporter: impl Into<String>,
        target_ref: impl Into<String>,
    ) -> Self {
        let actor_id = actor_id.into();
        Self {
            realm_id: realm_id.into(),
            session_actor_id: actor_id.clone(),
            actor_id,
            kind: arkret_wire::EventKind::SelfModerationReport
                .as_str()
                .to_owned(),
            device_id: "moderation-report-service".to_owned(),
            binding: InternalEventBinding::MimiModerationReport {
                reporter: reporter.into(),
                target_ref: target_ref.into(),
            },
        }
    }

    pub(in crate::routing) fn applet_formal(
        realm_id: impl Into<String>,
        actor_id: impl Into<String>,
        kind: impl Into<String>,
        event_id: impl Into<String>,
    ) -> Self {
        let actor_id = actor_id.into();
        Self {
            realm_id: realm_id.into(),
            session_actor_id: actor_id.clone(),
            actor_id,
            kind: kind.into(),
            device_id: "applet-service".to_owned(),
            binding: InternalEventBinding::AppletFormal {
                event_id: event_id.into(),
            },
        }
    }

    pub(in crate::routing) fn sidecar_ensure(
        realm_id: impl Into<String>,
        actor_id: impl Into<String>,
        device_id: impl Into<String>,
        kind: impl Into<String>,
        event_id: impl Into<String>,
    ) -> Self {
        let actor_id = actor_id.into();
        Self {
            realm_id: realm_id.into(),
            session_actor_id: actor_id.clone(),
            actor_id,
            kind: kind.into(),
            device_id: device_id.into(),
            binding: InternalEventBinding::SidecarEnsure {
                event_id: event_id.into(),
            },
        }
    }

    pub(in crate::routing) fn peer_federated_event(
        realm_id: impl Into<String>,
        actor_id: impl Into<String>,
        device_id: impl Into<String>,
        event_id: impl Into<String>,
        signer_key_evidence: Vec<arkret_wire::event_envelope::FederatedDeviceSigningKeyEvidence>,
        agent_signer_evidence: Vec<VerifiedFederatedAgentSignerEvidence>,
    ) -> Self {
        let actor_id = actor_id.into();
        Self {
            realm_id: realm_id.into(),
            session_actor_id: actor_id.clone(),
            actor_id,
            kind: String::new(),
            device_id: device_id.into(),
            binding: InternalEventBinding::PeerFederatedEvent {
                event_id: event_id.into(),
                signer_key_evidence,
                agent_signer_evidence,
            },
        }
    }

    pub(in crate::routing::events::event_log) fn matches(
        &self,
        session: &SessionRecord,
        object: &serde_json::Map<String, Value>,
    ) -> bool {
        session.actor == self.session_actor_id
            && session.device_id == self.device_id
            && object.get("actor_id").and_then(Value::as_str) == Some(self.actor_id.as_str())
            && object.get("realm_id").and_then(Value::as_str) == Some(self.realm_id.as_str())
            && (self.kind.is_empty()
                || object.get("kind").and_then(Value::as_str) == Some(self.kind.as_str()))
            && match &self.binding {
                InternalEventBinding::MimiProvider { binding_ref } => {
                    object
                        .get("payload")
                        .and_then(|payload| payload.get("metadata"))
                        .and_then(|metadata| metadata.get("mimi_provenance"))
                        .and_then(|provenance| provenance.get("mimi_room_binding_ref"))
                        .and_then(Value::as_str)
                        == Some(binding_ref.as_str())
                }
                InternalEventBinding::AccountData { owner, key } => {
                    object.get("payload").is_some_and(|payload| {
                        payload.get("owner").and_then(Value::as_str) == Some(owner.as_str())
                            && payload.get("key").and_then(Value::as_str) == Some(key.as_str())
                    })
                }
                InternalEventBinding::MimiModerationReport {
                    reporter,
                    target_ref,
                } => object.get("payload").is_some_and(|payload| {
                    payload.get("reporter").and_then(Value::as_str) == Some(reporter.as_str())
                        && payload.get("target_ref").and_then(Value::as_str)
                            == Some(target_ref.as_str())
                }),
                InternalEventBinding::AppletFormal { event_id }
                | InternalEventBinding::SidecarEnsure { event_id } => {
                    object.get("event_id").and_then(Value::as_str) == Some(event_id.as_str())
                }
                InternalEventBinding::PeerFederatedEvent { event_id, .. } => {
                    object.get("event_id").and_then(Value::as_str) == Some(event_id.as_str())
                }
            }
    }

    pub(in crate::routing::events::event_log) fn signer_key_evidence(
        &self,
        session: &SessionRecord,
        object: &serde_json::Map<String, Value>,
        verification_method: &str,
    ) -> Option<&arkret_wire::event_envelope::FederatedDeviceSigningKeyEvidence> {
        if !self.matches(session, object) {
            return None;
        }
        let evidence = match &self.binding {
            InternalEventBinding::PeerFederatedEvent {
                signer_key_evidence,
                ..
            } => signer_key_evidence,
            _ => return None,
        };
        evidence.iter().find(|entry| {
            entry.actor_id.as_str() == self.actor_id
                && entry.verification_method == verification_method
                && entry.validate_shape().is_ok()
        })
    }

    pub(in crate::routing::events::event_log) fn agent_signer_evidence(
        &self,
        session: &SessionRecord,
        object: &serde_json::Map<String, Value>,
        verification_method: &str,
    ) -> Option<&VerifiedFederatedAgentSignerEvidence> {
        if !self.matches(session, object) || object.get("applet_id").is_some() {
            return None;
        }
        let InternalEventBinding::PeerFederatedEvent {
            agent_signer_evidence,
            ..
        } = &self.binding
        else {
            return None;
        };
        let actor = object.get("actor_id").and_then(Value::as_str)?;
        let signer = object
            .get("executed_by")
            .and_then(Value::as_str)
            .unwrap_or(actor);
        agent_signer_evidence.iter().find(|entry| {
            signer == entry.agent_id.as_str()
                && verification_method == entry.verification_method.as_str()
        })
    }

    pub(in crate::routing::events::event_log) fn authorizes_realm_membership_bypass(
        &self,
        session: &SessionRecord,
        object: &serde_json::Map<String, Value>,
    ) -> bool {
        self.matches(session, object)
            && !matches!(
                &self.binding,
                InternalEventBinding::PeerFederatedEvent { .. }
            )
    }

    pub(in crate::routing::events::event_log) fn is_sidecar_ensure(
        &self,
        session: &SessionRecord,
        object: &serde_json::Map<String, Value>,
    ) -> bool {
        matches!(self.binding, InternalEventBinding::SidecarEnsure { .. })
            && self.matches(session, object)
    }
}

const DELIVERY_BINDING_HANDOVER_GRACE_SECONDS: i64 = 86_400;

#[derive(Debug, Clone)]
struct DeliveryBindingMemberView {
    member: String,
    realm_id: String,
    recipient_service_id: String,
    membership_event_ref: Option<String>,
    delivery_binding_frontier_ref: String,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
struct DeliveryBindingHandoverEvidence {
    realm_id: String,
    actor_id: arkret_wire::DidCoreId,
    new_recipient_service_id: arkret_wire::DidCoreId,
    new_service_resolution: Option<arkret_models_identity::ServiceResolutionCarrier>,
    handover_frontier: Vec<EventId>,
    membership_event_ref: Option<String>,
    delivery_binding_frontier_ref: String,
    updated_at: DateTime<Utc>,
    witness: Value,
}

#[derive(Debug, Clone)]
enum FederationServiceBindingCheck {
    Current,
    Reject(&'static str),
    Stale(DeliveryBindingHandoverEvidence),
    HandedOver(DeliveryBindingHandoverEvidence),
}

impl SubmitOneError {
    pub(in crate::routing) fn new(
        status: StatusCode,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            status,
            code: code.into(),
            message: message.into(),
            details: None,
            quarantine_event_id: None,
        }
    }

    pub(in crate::routing) fn with_details(mut self, details: impl serde::Serialize) -> Self {
        self.details = serde_json::to_value(details).ok();
        self
    }

    pub(in crate::routing) fn quarantine(
        event_id: impl Into<String>,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            status: StatusCode::OK,
            code: code.into(),
            message: message.into(),
            details: None,
            quarantine_event_id: Some(event_id.into()),
        }
    }
}

/// Map a rejected Event submission onto the HTTP error family without losing the
/// wire discriminator.
///
/// A caller-signed Event that ordinary admission rejects has a real reason, and
/// `context` names the surface that submitted it. Reducer rejection reasons (for
/// example `circle_realm_mismatch` or `grant_exceeds_issuer_authority`) are
/// stable *reason* codes, not top-level error codes: one that is not a registered
/// error code keeps its semantic HTTP class and travels in `reason_code`, rather
/// than being flattened into a misleading 500 internal_error.
pub(in crate::routing) fn submit_one_error_to_app_error(
    context: &str,
    status: StatusCode,
    code: String,
    detail: &str,
) -> AppError {
    let message = format!("{context}: {detail}");
    if let Some(mapped) = ErrorCode::from_wire(&code) {
        return AppError::new(mapped, message).with_status(status);
    }
    let mapped = match status {
        StatusCode::PRECONDITION_FAILED => ErrorCode::FailedPrecondition,
        StatusCode::CONFLICT => ErrorCode::Conflict,
        StatusCode::FORBIDDEN => ErrorCode::CapabilityDenied,
        StatusCode::UNAUTHORIZED => ErrorCode::Unauthenticated,
        StatusCode::BAD_REQUEST => ErrorCode::InvalidParam,
        StatusCode::UNPROCESSABLE_ENTITY => ErrorCode::SchemaViolation,
        _ => ErrorCode::InternalError,
    };
    AppError::new(mapped, message)
        .with_status(status)
        .with_reason_code(code)
}

fn realm_already_exists_error() -> SubmitOneError {
    SubmitOneError::new(
        StatusCode::CONFLICT,
        "realm_already_exists",
        "realm already exists",
    )
}

fn cba_bottom_reject(reason: &'static str) -> (&'static str, &'static str) {
    if reason == "cell_bottom_state" {
        ("failed_bottom", "cell_in_bottom_state")
    } else {
        (reason, reason)
    }
}

impl From<EventValidationError> for SubmitOneError {
    fn from(error: EventValidationError) -> Self {
        let mut rendered = Self::new(error.status, error.code, error.message);
        if let Some(reason_code) = error.reason_code {
            rendered = rendered.with_details(serde_json::json!({
                "reason_code": reason_code,
            }));
        }
        rendered
    }
}

pub(super) fn event_validation_error(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
) -> EventValidationError {
    EventValidationError {
        status,
        code,
        message: message.into(),
        reason_code: None,
    }
}

pub(super) fn render_submit_one_error(res: &mut Response, error: SubmitOneError) {
    if let Some(event_id) = error.quarantine_event_id {
        res.render(Json(events_submit_outcome(
            EventsSubmitStatus::Partial,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![event_id],
            None,
        )));
        return;
    }
    if let Some(details) = error.details {
        let mut envelope =
            arkret_wire::problem_details::ErrorEnvelope::new(error.code, error.message)
                .with_request_id(crate::ids::generate_request_id());
        if let Some(object) = details.as_object() {
            for (key, value) in object {
                envelope = envelope.with_detail(key.clone(), value.clone());
            }
        }
        res.status_code(error.status);
        res.render(Json(envelope));
    } else if error.status == StatusCode::PRECONDITION_FAILED
        && error.code == "failed_precondition"
        && error.message != error.code
    {
        soland_http::util::render_error_with_top_level_reason(
            res,
            error.status,
            &error.code,
            &error.message,
            &error.message,
            None,
        );
    } else {
        render_error(res, error.status, &error.code, &error.message);
    }
}

pub(super) async fn submit_event_batch(
    state: &AppState,
    session: &SessionRecord,
    envelopes: Vec<Value>,
    res: &mut Response,
) {
    match submit_event_batch_outcome(state, session, envelopes).await {
        Ok(outcome) => res.render(Json(outcome)),
        Err(error) => render_submit_one_error(res, error),
    }
}

/// Run a multi-envelope batch and return its `EventsSubmitOutcome` without
/// rendering, so the caller can also feed the value through the generic
/// `Idempotency-Key` cache (api-conventions.md §6) before rendering. The batch
/// surface never produces a 409 on its own — per-envelope conflicts are folded
/// into `rejected[]` / `quarantine[]` and the aggregate status is `partial` —
/// so only the two early body-shape guards short-circuit as a `SubmitOneError`.
pub(super) async fn submit_event_batch_outcome(
    state: &AppState,
    session: &SessionRecord,
    envelopes: Vec<Value>,
) -> Result<EventsSubmitOutcome, SubmitOneError> {
    submit_event_batch_outcome_with_leases(state, session, envelopes, None, None, None).await
}

pub(in crate::routing) async fn submit_initial_event_batch_outcome(
    state: &AppState,
    session: &SessionRecord,
    submissions: Vec<arkret_wire::EventInitialSubmission>,
) -> Result<EventsSubmitOutcome, SubmitOneError> {
    let mut envelopes = Vec::with_capacity(submissions.len());
    let mut typed_events = Vec::with_capacity(submissions.len());
    let mut leases = Vec::with_capacity(submissions.len());
    let mut control_proposal_acks = Vec::with_capacity(submissions.len());
    let mut compensation_evidence = Vec::with_capacity(submissions.len());
    for submission in &submissions {
        typed_events.push(submission.event.clone());
        envelopes.push(typed_event_to_canonical_value(submission.event.clone())?);
    }
    let submit_context =
        if batch_contains_identity_anchor(&envelopes) || batch_begins_realm_create(&envelopes) {
            arkret_wire::EventSubmitContext::AnchorUnit
        } else {
            arkret_wire::EventSubmitContext::Standard
        };
    for submission in submissions {
        validate_initial_submission_in_context(&submission, submit_context)?;
        if let Some(lease) = &submission.authorization_lease {
            validate_authorization_lease_for_event(state, Some(session), &submission.event, lease)
                .await?;
        }
        let arkret_wire::EventInitialSubmission {
            event: _,
            authorization_lease,
            cba_proof_bundles: _,
            control_proposal_ack,
            membership_compensation_evidence,
        } = submission;
        leases.push(authorization_lease);
        control_proposal_acks.push(control_proposal_ack);
        compensation_evidence.push(membership_compensation_evidence);
    }
    if submit_context == arkret_wire::EventSubmitContext::AnchorUnit
        && leases.iter().any(Option::is_some)
    {
        let complete_leases = leases
            .iter()
            .cloned()
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| {
                SubmitOneError::new(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    "an anchor unit cannot mix online and delayed submissions",
                )
            })?;
        arkret_wire::validate_anchor_unit_lease_bindings(&typed_events, &complete_leases).map_err(
            |error| {
                SubmitOneError::new(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    format!("anchor-unit publication evidence is invalid: {error}"),
                )
            },
        )?;
    }
    submit_event_batch_outcome_with_leases(
        state,
        session,
        envelopes,
        Some(&leases),
        Some(&control_proposal_acks),
        Some(&compensation_evidence),
    )
    .await
}

pub(in crate::routing) async fn submit_direct_conversation_founding_unit(
    state: &AppState,
    session: &SessionRecord,
    submission: DirectConversationFoundingUnitSubmission,
) -> Result<DirectConversationFoundingAcceptanceOutcome, SubmitOneError> {
    let typed_events = submission
        .events
        .iter()
        .map(|submission| &submission.event)
        .collect::<Vec<_>>();
    let exact: [&arkret_wire::Event; 3] = typed_events
        .try_into()
        .expect("typed founding carrier has exactly three Events");
    let plan = DirectConversationFoundingPlan::from_events(exact).map_err(|error| {
        SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "direct_conversation_founding_unit_invalid",
            error.to_string(),
        )
    })?;
    let trust_domain_id = state.config().trust_domain.clone();
    let (pair_key, founder_id, authorization_core) = match &submission.founder_basis_evidence {
        evidence @ arkret_models_collaboration::direct_conversation_ops::DirectConversationFounderBasisEvidence::Human { .. } => {
            evidence
                .human_pair_key_and_authorization_core(trust_domain_id.clone())
                .map_err(|error| {
                    SubmitOneError::new(
                        StatusCode::BAD_REQUEST,
                        "direct_conversation_founding_unit_invalid",
                        error.to_string(),
                    )
                })?
        }
        arkret_models_collaboration::direct_conversation_ops::DirectConversationFounderBasisEvidence::ControllerAgent {
            agent_provision_ref,
            agent_provision_digest,
            controller_binding_digest,
        } => {
            let member_payload: arkret_models_collaboration::governance::membership_invite::MembershipPayload =
                serde_json::from_value(serde_json::to_value(&submission.events[1].event.payload).map_err(|error| {
                    SubmitOneError::new(StatusCode::BAD_REQUEST, "direct_conversation_founding_unit_invalid", error.to_string())
                })?).map_err(|error| SubmitOneError::new(StatusCode::BAD_REQUEST, "direct_conversation_founding_unit_invalid", error.to_string()))?;
            let peer = member_payload.actor_id.ok_or_else(|| SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "direct_conversation_founding_unit_invalid",
                "controller-Agent founding peer membership has no actor_id",
            ))?;
            let founder = submission.events[0].event.actor_id.clone();
            let pair_key = arkret_models_collaboration::objects::direct_conversation::direct_conversation_pair_key(
                trust_domain_id.clone(),
                arkret_models_collaboration::objects::direct_conversation::DirectConversationPairKeyParticipant::unmapped(founder.clone()),
                arkret_models_collaboration::objects::direct_conversation::DirectConversationPairKeyParticipant::unmapped(
                    peer,
                ),
            ).map_err(|error| SubmitOneError::new(StatusCode::BAD_REQUEST, "direct_conversation_founding_unit_invalid", error.to_string()))?;
            (
                pair_key,
                founder,
                DirectConversationFoundingAuthorizationCore::ControllerAgent {
                    agent_provision_ref: agent_provision_ref.clone(),
                    agent_provision_digest: agent_provision_digest.clone(),
                    controller_binding_digest: controller_binding_digest.clone(),
                },
            )
        }
    };
    if founder_id.as_str() != session.actor || submission.events[0].event.actor_id != founder_id {
        return Err(SubmitOneError::new(
            StatusCode::FORBIDDEN,
            "capability_denied",
            "only the founder derived from the root basis may submit this unit",
        ));
    }
    submission
        .source_service_binding
        .validate_shape()
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "direct_conversation_founding_unit_invalid",
                format!("source service binding is invalid: {error}"),
            )
        })?;
    if submission.source_service_binding.principal_id.as_str() != founder_id.as_str()
        || submission.source_service_binding.service_id.as_str() != state.service_id()
    {
        return Err(SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "direct_conversation_founding_unit_invalid",
            "source service binding does not bind the founder to this service",
        ));
    }
    if let Some(stored) = state
        .event_queries()
        .direct_conversation_founding_slot(
            founder_id.as_str(),
            trust_domain_id.as_str(),
            pair_key.as_str(),
        )
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                error.to_string(),
            )
        })?
        && stored.idempotency_key == submission.idempotency_key.as_str()
        && stored.founding_unit_digest == plan.founding_unit_digest.as_str()
    {
        let stored_receipt = serde_json::from_slice(&stored.receipt_bytes).map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("stored founding receipt is invalid: {error}"),
            )
        })?;
        return Ok(DirectConversationFoundingAcceptanceOutcome {
            unit_kind: DirectConversationFoundingUnitKind::DirectConversationFounding,
            status: DirectConversationFoundingAcceptanceStatus::Duplicate,
            event_ids: plan.event_ids,
            receipt: stored_receipt,
        });
    }
    let accepted_at = now();
    match &submission.founder_basis_evidence {
        arkret_models_collaboration::direct_conversation_ops::DirectConversationFounderBasisEvidence::Human {
            basis_evidence_bundle,
            ..
        } => {
            let ([left, right], _) = submission
                .founder_basis_evidence
                .participants_and_founder()
                .map_err(|error| {
                    SubmitOneError::new(
                        StatusCode::BAD_REQUEST,
                        "direct_conversation_founding_unit_invalid",
                        error.to_string(),
                    )
                })?;
            let current = crate::routing::identity::account::accepted_contact_for_pair(
                state,
                left.as_str(),
                right.as_str(),
                "direct_message",
            )
            .await
            .map_err(|error| {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    error.to_string(),
                )
            })?
            .ok_or_else(|| {
                SubmitOneError::new(
                    StatusCode::CONFLICT,
                    "failed_precondition",
                    "current two-direction direct_message Contact gate is not accepted",
                )
            })?;
            let current_heads = [
                current.request_event_ref.as_deref(),
                current.response_event_ref.as_deref(),
            ]
            .into_iter()
            .flatten()
            .collect::<std::collections::BTreeSet<_>>();
            let evidence_heads = basis_evidence_bundle
                .current_proofs
                .iter()
                .map(|proof| proof.head_event_ref.as_str())
                .collect::<std::collections::BTreeSet<_>>();
            if current.basis_id.as_deref() != Some(basis_evidence_bundle.basis_id.as_str())
                || current_heads != evidence_heads
                || basis_evidence_bundle
                    .current_proofs
                    .iter()
                    .any(|proof| proof.terminal || proof.fresh_until <= accepted_at)
            {
                return Err(SubmitOneError::new(
                    StatusCode::CONFLICT,
                    "failed_precondition",
                    "founding evidence does not match the fresh current Contact heads",
                ));
            }
        }
        arkret_models_collaboration::direct_conversation_ops::DirectConversationFounderBasisEvidence::ControllerAgent {
            agent_provision_ref,
            agent_provision_digest,
            ..
        } => {
            let member_payload: arkret_models_collaboration::governance::membership_invite::MembershipPayload =
                serde_json::from_value(serde_json::to_value(&submission.events[1].event.payload).map_err(|error| {
                    SubmitOneError::new(StatusCode::BAD_REQUEST, "direct_conversation_founding_unit_invalid", error.to_string())
                })?).map_err(|error| SubmitOneError::new(StatusCode::BAD_REQUEST, "direct_conversation_founding_unit_invalid", error.to_string()))?;
            let agent_id = member_payload.actor_id.ok_or_else(|| SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "direct_conversation_founding_unit_invalid",
                "controller-Agent founding peer membership has no actor_id",
            ))?;
            let agent = state
                .agent_pairings()
                .agent(agent_id.as_str())
                .await
                .map_err(|error| SubmitOneError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", error.to_string()))?
                .ok_or_else(|| SubmitOneError::new(StatusCode::CONFLICT, "failed_precondition", "accepted Agent provision is unavailable"))?;
            let stored_provision_ref = agent
                .provision_event_refs
                .as_ref()
                .and_then(|refs| refs.get("provision_event_id"))
                .and_then(Value::as_str);
            let accepted_provision = state
                .event_queries()
                .accepted_event(agent_provision_ref.as_str())
                .await
                .map_err(|error| SubmitOneError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", error.to_string()))?
                .ok_or_else(|| SubmitOneError::new(StatusCode::CONFLICT, "failed_precondition", "accepted Agent provision Event is unavailable"))?;
            if agent.controller_id != founder_id.as_str()
                || agent.state
                    != arkret_models_collaboration::agent_operations::AgentLifecycleState::Active
                || stored_provision_ref != Some(agent_provision_ref.as_str())
                || accepted_provision.kind != arkret_wire::EventKind::AgentProvision.as_str()
                || accepted_provision.canonical_digest != agent_provision_digest.as_str()
            {
                return Err(SubmitOneError::new(
                    StatusCode::CONFLICT,
                    "failed_precondition",
                    "controller-Agent founding evidence does not match the current provision",
                ));
            }
            crate::routing::identity::managed_agent_pcr::validate_agent_controller_binding(
                state,
                &agent,
                accepted_at,
            )
            .await
            .map_err(|error| {
                SubmitOneError::new(
                    StatusCode::CONFLICT,
                    "failed_precondition",
                    error.to_string(),
                )
            })?;
        }
    }
    let issuer_service_id =
        arkret_wire::DidCoreId::new(state.service_id().clone()).map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("service DID is invalid: {error}"),
            )
        })?;
    verify_accepted_principal_service_binding(&submission.source_service_binding, state)
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "invalid_proof",
                format!("source service binding is invalid: {error}"),
            )
        })?;
    if submission.source_service_binding.principal_id.as_str() != founder_id.as_str()
        || submission.source_service_binding.service_id != issuer_service_id
        || submission.source_service_binding.accepted_at > accepted_at
        || submission
            .source_service_binding
            .expires_at
            .is_some_and(|until| until < accepted_at)
    {
        return Err(SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "source service binding does not authorize this founder/service at acceptance",
        ));
    }
    let (_, verification_method) =
        state
            .current_service_receipt_binding()
            .await
            .map_err(|error| {
                SubmitOneError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("service receipt binding is unavailable: {error}"),
                )
            })?;
    if verification_method
        != submission
            .source_service_binding
            .service_verification_method
            .id
    {
        return Err(SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "source service binding does not use the current service assertion method",
        ));
    }
    let mut receipt = DirectConversationFoundingAcceptanceReceipt {
        pair_key: pair_key.clone(),
        founder_id: founder_id.clone(),
        realm_id: plan.realm_id.clone(),
        main_strand_id: plan.main_strand_id.clone(),
        founding_unit_digest: plan.founding_unit_digest.clone(),
        authorization_core,
        slot_committed: true,
        issuer_service_id,
        issuer_service_binding_digest: submission.source_service_binding.binding_digest.clone(),
        accepted_at,
        proof: arkret_wire::ProtocolSignature {
            verification_method,
            created_at: accepted_at,
            jws: arkret_wire::Base64UrlString::new("AA".to_owned()).expect("static base64url"),
        },
    };
    let signing_input = receipt.signing_input_bytes().map_err(|error| {
        SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            error.to_string(),
        )
    })?;
    let signature =
        URL_SAFE_NO_PAD.encode(state.notary_signing_key().sign(&signing_input).to_bytes());
    receipt.proof.jws = arkret_wire::Base64UrlString::new(signature).map_err(|error| {
        SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            error.to_string(),
        )
    })?;
    let receipt_bytes = canonical::canonical_json_bytes(&receipt).map_err(|error| {
        SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            error.to_string(),
        )
    })?;
    let slot = soland_storage::DirectConversationFoundingSlotRecord {
        founder_id: founder_id.to_string(),
        trust_domain_id: trust_domain_id.to_string(),
        pair_key: pair_key.to_string(),
        founding_unit_digest: plan.founding_unit_digest.to_string(),
        realm_id: plan.realm_id.to_string(),
        main_strand_id: plan.main_strand_id.to_string(),
        event_ids: plan.event_ids.iter().map(ToString::to_string).collect(),
        idempotency_key: submission.idempotency_key.to_string(),
        receipt_bytes,
        accepted_at,
    };
    let envelopes = submission
        .events
        .iter()
        .map(|submission| typed_event_to_canonical_value(submission.event.clone()))
        .collect::<Result<Vec<_>, _>>()?;
    let leases = submission
        .events
        .iter()
        .map(|event| event.authorization_lease.clone())
        .collect::<Vec<_>>();
    let basis_evidence = submission.founder_basis_evidence.clone();
    let ordinary_outcome = submit_realm_bootstrap_batch(
        state,
        session,
        envelopes,
        None,
        Some(&leases),
        Some(realm_bootstrap::DirectConversationFoundingCommitContext {
            slot,
            receipt: receipt.clone(),
            founder_basis_evidence: basis_evidence,
            source_service_binding: submission.source_service_binding.clone(),
        }),
    )
    .await?;
    let stored = state
        .event_queries()
        .direct_conversation_founding_slot(
            founder_id.as_str(),
            trust_domain_id.as_str(),
            pair_key.as_str(),
        )
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                error.to_string(),
            )
        })?
        .ok_or_else(|| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "founding slot disappeared after commit",
            )
        })?;
    let stored_receipt: DirectConversationFoundingAcceptanceReceipt =
        serde_json::from_slice(&stored.receipt_bytes).map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                error.to_string(),
            )
        })?;
    Ok(DirectConversationFoundingAcceptanceOutcome {
        unit_kind: DirectConversationFoundingUnitKind::DirectConversationFounding,
        status: if ordinary_outcome.status == EventsSubmitStatus::Duplicate {
            DirectConversationFoundingAcceptanceStatus::Duplicate
        } else {
            DirectConversationFoundingAcceptanceStatus::Accepted
        },
        event_ids: plan.event_ids,
        receipt: stored_receipt,
    })
}

async fn submit_event_batch_outcome_with_leases(
    state: &AppState,
    session: &SessionRecord,
    envelopes: Vec<Value>,
    authorization_leases: Option<&[Option<arkret_wire::AuthorizationLease>]>,
    control_proposal_acks: Option<&[Option<arkret_wire::ControlProposalAck>]>,
    membership_compensation_evidence: Option<
        &[Option<arkret_wire::MembershipCompensationSubmissionEvidence>],
    >,
) -> Result<EventsSubmitOutcome, SubmitOneError> {
    if authorization_leases.is_some_and(|leases| leases.len() != envelopes.len()) {
        return Err(SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "initial publication batch lease cardinality mismatch",
        ));
    }
    if control_proposal_acks.is_some_and(|acks| acks.len() != envelopes.len()) {
        return Err(SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "initial publication batch control-proposal-ack cardinality mismatch",
        ));
    }
    if membership_compensation_evidence.is_some_and(|evidence| evidence.len() != envelopes.len()) {
        return Err(SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "initial publication batch compensation-evidence cardinality mismatch",
        ));
    }
    if envelopes.is_empty() {
        return Err(SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "missing_param",
            "events submit batch must contain at least one envelope",
        ));
    }
    if arkret_wire::event_envelope::validate_event_submit_batch_count(envelopes.len()).is_err() {
        return Err(SubmitOneError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "events submit batch exceeds max batch size",
        ));
    }
    // strand-and-message.md 8.4: a cross-actor `.others` watch write is only admissible with
    // its `ak.audit.accessed` partner in the same batch. The pairing is checked here rather
    // than per envelope because the audit Event is authored after the write it records — the
    // two cannot name each other (encoding.md 6.0.1), so neither is decidable alone.
    validate_watch_set_others_audit_pairs(state, &envelopes).map_err(SubmitOneError::from)?;
    if batch_contains_identity_anchor(&envelopes) {
        return submit_identity_anchor_batch(
            state,
            session,
            envelopes,
            authorization_leases,
            control_proposal_acks,
            None,
            None,
        )
        .await;
    }
    if batch_begins_realm_create(&envelopes) && !batch_is_managed_agent_pcr_create(&envelopes) {
        return submit_realm_bootstrap_batch(
            state,
            session,
            envelopes,
            None,
            authorization_leases,
            None,
        )
        .await;
    }
    let mut accepted = Vec::new();
    let mut duplicate = Vec::new();
    let mut rejected = Vec::new();
    let mut quarantine = Vec::new();
    let mut ingress_receipts = Vec::new();
    let mut realm_actor_frontiers = BTreeMap::new();
    let mut realm_bootstrap_contexts: Vec<RealmBootstrapBatchContext> = Vec::new();
    // `event-auth-state-resolution.md` §5(1) — the managed Agent PCR genesis is
    // the delegated branch of the closed `ak.realm.create` anchor unit, so its
    // create carries no `seal_basis` and its registry plane check must run in
    // the bootstrap context. The ordinary-Realm branch already returned above;
    // reaching here with a leading create means this branch, and
    // `batch_is_managed_agent_pcr_create` has already materialized the unit.
    if batch_begins_realm_create(&envelopes)
        && batch_is_managed_agent_pcr_create(&envelopes)
        && let (Some(realm_id), Some(actor_id)) = (
            event_realm_id_from_value(&envelopes[0]),
            event_string_field_from_value(&envelopes[0], "actor_id"),
        )
    {
        realm_bootstrap_contexts.push(RealmBootstrapBatchContext {
            realm_id,
            actor_id,
            digest_algorithm: Some(staged_realm_digest_algorithm(&envelopes[0])),
            identity_anchor_event_id: None,
            self_principal_pcr_bootstrap: false,
            identity_anchor_candidate_device: None,
            identity_anchor_resolution: None,
            direct_conversation_founding: false,
            authority_root: None,
        });
    }

    for (index, envelope) in envelopes.into_iter().enumerate() {
        let id = event_string_field_from_value(&envelope, "event_id")
            .unwrap_or_else(|| "unknown".to_owned());
        let kind = event_string_field_from_value(&envelope, "kind");
        let realm_id = event_string_field_from_value(&envelope, "realm_id");
        let actor_id = event_string_field_from_value(&envelope, "actor_id");
        match submit_event_value_with_context(
            state,
            session,
            envelope.clone(),
            &realm_bootstrap_contexts,
            None,
            None,
            authorization_leases
                .and_then(|leases| leases.get(index))
                .and_then(Option::as_ref),
            control_proposal_acks
                .and_then(|acks| acks.get(index))
                .and_then(Option::as_ref),
            membership_compensation_evidence
                .and_then(|evidence| evidence.get(index))
                .and_then(Option::as_ref),
            None,
            false,
            None,
            &[],
            None,
        )
        .await
        {
            Ok(response) => {
                for frontier in response.outcome.realm_actor_frontiers.iter().cloned() {
                    realm_actor_frontiers.insert(
                        (
                            frontier.realm_id.as_str().to_owned(),
                            frontier.actor_id.as_str().to_owned(),
                        ),
                        frontier,
                    );
                }
                ingress_receipts.extend(response.outcome.ingress_receipts.iter().cloned());
                accepted.push(response.event_id.clone());
                if response.duplicate {
                    duplicate.push(response.event_id);
                }
                if !response.duplicate
                    && kind.as_deref() == Some(arkret_wire::EventKind::RealmCreate.as_str())
                    && let (Some(realm_id), Some(actor_id)) = (realm_id, actor_id)
                {
                    realm_bootstrap_contexts.push(RealmBootstrapBatchContext {
                        realm_id,
                        actor_id,
                        digest_algorithm: Some(staged_realm_digest_algorithm(&envelope)),
                        identity_anchor_event_id: None,
                        self_principal_pcr_bootstrap: false,
                        identity_anchor_candidate_device: None,
                        identity_anchor_resolution: None,
                        direct_conversation_founding: false,
                        authority_root: None,
                    });
                }
            }
            Err(error) => {
                if let Some(event_id) = error.quarantine_event_id {
                    quarantine.push(event_id);
                } else {
                    rejected.push(rejected_item(
                        id,
                        ReasonCode::from_wire(&error.code),
                        Some(error.message),
                    ));
                }
            }
        }
    }

    let status = if !rejected.is_empty() || !quarantine.is_empty() {
        EventsSubmitStatus::Partial
    } else if accepted.len() == duplicate.len() && !duplicate.is_empty() {
        EventsSubmitStatus::Duplicate
    } else {
        EventsSubmitStatus::Accepted
    };
    let cursor = if let Some(event_id) = accepted.last() {
        Some(super::super::sync::sync_barrier_token_for_event(state, session, event_id).await)
    } else {
        None
    };
    let mut outcome =
        events_submit_outcome(status, accepted, duplicate, rejected, quarantine, cursor);
    outcome.ingress_receipts = ingress_receipts;
    outcome.realm_actor_frontiers = realm_actor_frontiers.into_values().collect();
    Ok(outcome)
}

/// Submit a closed two-Event identity-anchor unit with publication evidence.
/// Validation, Event rows, re-anchor receipt/device projection, and both
/// ingress receipts are committed as one storage transaction.
pub(in crate::routing) async fn submit_initial_identity_anchor_batch(
    state: &AppState,
    session: &SessionRecord,
    submissions: Vec<arkret_wire::EventInitialSubmission>,
) -> Result<EventsSubmitOutcome, SubmitOneError> {
    let submit_context = if submissions.len() == 2
        && submissions[0].event.kind == arkret_wire::EventKind::DeviceReanchor
        && submissions[1].event.kind == arkret_wire::EventKind::DeviceAuthorize
    {
        arkret_wire::EventSubmitContext::AnchorUnit
    } else {
        arkret_wire::EventSubmitContext::Standard
    };
    for submission in &submissions {
        validate_initial_submission_in_context(submission, submit_context)?;
    }
    let envelopes = submissions
        .iter()
        .map(|submission| typed_event_to_canonical_value(submission.event.clone()))
        .collect::<Result<Vec<_>, _>>()?;
    let (leases, control_proposal_acks): (Vec<_>, Vec<_>) = submissions
        .into_iter()
        .map(|submission| {
            (
                submission.authorization_lease,
                submission.control_proposal_ack,
            )
        })
        .unzip();
    submit_identity_anchor_batch(
        state,
        session,
        envelopes,
        Some(&leases),
        Some(&control_proposal_acks),
        None,
        None,
    )
    .await
}

/// Accept the one registered pre-grant PCR genesis carrier after the peer
/// transport has authenticated the Account Authority service.
pub(in crate::routing) async fn submit_peer_pcr_genesis(
    state: &AppState,
    request: &arkret_models_collaboration::principal_operations::PcrGenesisSubmitRequestBody,
) -> Result<
    arkret_models_collaboration::principal_operations::PcrGenesisSubmitOutcome,
    SubmitOneError,
> {
    request.validate().map_err(|error| {
        SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            format!("invalid PCR genesis relay: {error}"),
        )
    })?;
    let create_payload: arkret_models_collaboration::events_payloads::RealmCreatePayload = request
        .genesis_unit
        .create()
        .typed_payload::<arkret_wire::event_spec::RealmCreate>()
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("invalid PCR genesis create payload: {error}"),
            )
        })?;
    let descriptor = create_payload
        .object
        .founding_device_descriptor
        .ok_or_else(|| {
            SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "PCR genesis omits its founding device descriptor",
            )
        })?;
    let accepted_device_id = descriptor.device_id.clone();
    if let Some(outcome) =
        existing_pcr_genesis_outcome(state, request, accepted_device_id.clone()).await?
    {
        return Ok(outcome);
    }
    // Only a new admission needs a currently valid creation proof. An exact
    // replay of a durably accepted unit above remains replayable after the
    // short-lived proof expires and returns the original signed receipt.
    validate_identity_creation_control_proof(state, request).await?;
    let now = Utc::now();
    let session = SessionRecord {
        token_hash: format!("principal-genesis:{}", request.idempotency_key),
        actor: request.principal_id.to_string(),
        device_id: accepted_device_id.to_string(),
        audience: state.service_id().clone(),
        session_public_key: None,
        agent_session: None,
        session_grant: None,
        expires_at: now + Duration::minutes(5),
        created_at: now,
        revoked_at: None,
    };
    let envelopes = request
        .genesis_unit
        .events
        .iter()
        .cloned()
        .map(typed_event_to_canonical_value)
        .collect::<Result<Vec<_>, _>>()?;
    submit_identity_anchor_batch(
        state,
        &session,
        envelopes,
        None,
        None,
        Some(&request.account_authority_id),
        Some(PcrGenesisPins {
            account_subject: request
                .identity_creation_control_proof
                .account_subject
                .clone(),
            did_version_id: request.did_version_id.clone(),
            log_head_digest: request.log_head_digest.clone(),
            control_key_digest: request.control_key_digest.clone(),
            registration_evidence_digest: request
                .registration_did_evidence
                .canonical_digest()
                .map_err(|error| {
                    SubmitOneError::new(
                        StatusCode::BAD_REQUEST,
                        "historical_did_evidence_invalid",
                        format!("registration evidence digest is invalid: {error}"),
                    )
                })?,
        }),
    )
    .await?;
    existing_pcr_genesis_outcome(state, request, accepted_device_id)
        .await?
        .ok_or_else(|| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "accepted PCR genesis receipt is unavailable",
            )
        })
}

async fn existing_pcr_genesis_outcome(
    state: &AppState,
    request: &arkret_models_collaboration::principal_operations::PcrGenesisSubmitRequestBody,
    accepted_device_id: arkret_wire::DeviceId,
) -> Result<
    Option<arkret_models_collaboration::principal_operations::PcrGenesisSubmitOutcome>,
    SubmitOneError,
> {
    let authorize_event_id = request.genesis_unit.founding_authorize().event_id.as_str();
    let receipt = state
        .event_queries()
        .canonical_batch_receipts_for_event(authorize_event_id)
        .await
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("PCR genesis receipt lookup failed: {error}"),
            )
        })?
        .into_iter()
        .find(|receipt| {
            receipt.issuer.as_str() == state.service_id()
                && receipt.pcr_genesis_scope().is_ok_and(|scope| {
                    scope.principal_id == request.principal_id
                        && scope.realm_id == request.pcr_realm_id
                        && scope.audience == request.account_authority_id
                        && scope.did_version_id == request.did_version_id
                        && scope.log_head_digest == request.log_head_digest
                        && scope.control_key_digest == request.control_key_digest
                        && request
                            .registration_did_evidence
                            .canonical_digest()
                            .is_ok_and(|digest| digest == scope.registration_evidence_digest)
                })
        });
    let Some(receipt) = receipt else {
        return Ok(None);
    };
    let outcome = arkret_models_collaboration::principal_operations::PcrGenesisSubmitOutcome {
        principal_id: request.principal_id.clone(),
        pcr_realm_id: request.pcr_realm_id.clone(),
        accepted_device_id,
        receipt,
    };
    outcome.validate_against(request).map_err(|error| {
        SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            format!("accepted PCR genesis outcome is invalid: {error}"),
        )
    })?;
    Ok(Some(outcome))
}

async fn validate_identity_creation_control_proof(
    state: &AppState,
    request: &arkret_models_collaboration::principal_operations::PcrGenesisSubmitRequestBody,
) -> Result<(), SubmitOneError> {
    let proof = &request.identity_creation_control_proof;
    let now = Utc::now();
    if proof.issued_at > now
        || proof.expires_at <= now
        || proof.expires_at - proof.issued_at > Duration::minutes(5)
        || proof.audience.as_str() != state.service_id().as_str()
        || request.registration_did_evidence.accepted_at > now
    {
        return Err(SubmitOneError::new(
            StatusCode::FORBIDDEN,
            "invalid_proof",
            "identity creation control proof is expired or has the wrong audience",
        ));
    }
    arkret_signatures::webvh::verify_identity_creation_control_proof(
        &request.registration_did_operation,
        proof,
    )
    .map_err(|error| {
        SubmitOneError::new(
            StatusCode::FORBIDDEN,
            "invalid_proof",
            format!("identity creation proof is invalid: {error}"),
        )
    })?;
    arkret_signatures::webvh::verify_registration_did_evidence_draft(
        &request.registration_did_operation,
        &request.registration_did_evidence.draft(),
    )
    .map_err(|error| {
        SubmitOneError::new(
            StatusCode::FORBIDDEN,
            "historical_did_evidence_invalid",
            format!("frozen registration DID evidence is invalid: {error}"),
        )
    })?;
    Ok(())
}

async fn direct_bootstrap_source_is_contact_authority(
    state: &AppState,
    source_service_id: &str,
    events: &[Value],
) -> bool {
    let Some(first) = events.first() else {
        return false;
    };
    if event_string_field_from_value(first, "kind").as_deref()
        != Some(arkret_wire::EventKind::RealmCreate.as_str())
    {
        return false;
    }
    let Some(creator) = event_string_field_from_value(first, "actor_id") else {
        return false;
    };
    let realm = first.get("payload").cloned().and_then(|payload| {
        serde_json::from_value::<arkret_models_collaboration::events_payloads::RealmCreatePayload>(
            payload,
        )
        .ok()
        .map(|payload| payload.object)
    });
    if realm.as_ref().is_none_or(|realm| {
        realm.purpose
            != arkret_models_collaboration::events_payloads::RealmPurpose::DirectConversation
    }) {
        return false;
    }
    let peer = events.iter().find_map(|event| {
        if event_string_field_from_value(event, "kind").as_deref()
            != Some(arkret_wire::EventKind::MemberState.as_str())
        {
            return None;
        }
        let payload = event.get("payload")?;
        if payload.get("membership").and_then(Value::as_str) != Some("join") {
            return None;
        }
        let peer = payload.get("actor_id").and_then(Value::as_str)?;
        if peer == creator {
            return None;
        }
        let binding = payload.get("delivery_binding")?;
        (binding.get("recipient_service_id").and_then(Value::as_str)
            == Some(state.service_id().as_str()))
        .then(|| peer.to_owned())
    });
    let Some(peer) = peer else {
        return false;
    };
    state
        .contacts()
        .contact_any(&creator, &peer)
        .await
        .ok()
        .flatten()
        .is_some_and(|contact| {
            contact.status == "accepted"
                && contact.peer_service_id.as_deref() == Some(source_service_id)
        })
}

async fn accept_federated_seal_prerequisite(
    state: &AppState,
    realm_id: &arkret_identifiers::RealmId,
    envelope: &Value,
    seals: &[arkret_wire::Seal],
) -> Result<(), AppError> {
    let mut roots = Vec::new();
    if let Some(seal_ref) = envelope.get("seal_ref").and_then(Value::as_str) {
        roots.push(
            arkret_identifiers::SealId::new(seal_ref.to_owned())
                .map_err(|error| AppError::invalid_param(format!("invalid seal_ref: {error}")))?,
        );
    }
    if let Some(leaves) = envelope
        .get("seal_basis")
        .and_then(|basis| basis.get("leaves"))
        .and_then(Value::as_array)
    {
        for leaf in leaves {
            let leaf = leaf.as_str().ok_or_else(|| {
                AppError::invalid_param("seal_basis.leaves must contain Seal ids")
            })?;
            roots.push(
                arkret_identifiers::SealId::new(leaf.to_owned()).map_err(|error| {
                    AppError::invalid_param(format!("invalid seal_basis leaf: {error}"))
                })?,
            );
        }
    }
    if roots.is_empty() {
        return Ok(());
    }

    let mut required = BTreeSet::new();
    for root in &roots {
        if state
            .projections()
            .seal_by_id(root)
            .map_err(|error| {
                AppError::internal(format!("read transported Seal prerequisite: {error}"))
            })?
            .is_some()
        {
            continue;
        }
        if !seals.iter().any(|seal| &seal.id == root) {
            return Err(AppError::new(
                ErrorCode::DependencyMissing,
                "Event Seal prerequisite is absent from local state and federation seals[]",
            ));
        }
        required.insert(root.clone());
    }
    if required.is_empty() {
        return Ok(());
    }
    loop {
        let before = required.len();
        let predecessors = seals
            .iter()
            .filter(|seal| required.contains(&seal.id))
            .flat_map(|seal| seal.predecessor_refs.iter().cloned())
            .collect::<Vec<_>>();
        required.extend(predecessors);
        if required.len() == before {
            break;
        }
    }
    let relevant = seals
        .iter()
        .filter(|seal| required.contains(&seal.id))
        .cloned()
        .collect::<Vec<_>>();
    for seal in &relevant {
        if &seal.realm_id != realm_id {
            return Err(AppError::new(
                ErrorCode::SchemaViolation,
                "federated Seal prerequisite belongs to another Realm",
            ));
        }
        for predecessor in &seal.predecessor_refs {
            if relevant
                .iter()
                .any(|candidate| &candidate.id == predecessor)
            {
                continue;
            }
            if state
                .projections()
                .seal_by_id(predecessor)
                .map_err(|error| {
                    AppError::internal(format!(
                        "read transported Seal predecessor prerequisite: {error}"
                    ))
                })?
                .is_none()
            {
                return Err(AppError::new(
                    ErrorCode::DependencyMissing,
                    "federated Seal prerequisite has a non-local missing predecessor",
                ));
            }
        }
    }
    let event =
        serde_json::from_value::<arkret_wire::Event>(envelope.clone()).map_err(|error| {
            AppError::new(
                ErrorCode::SchemaViolation,
                format!(
                    "federated Event is invalid while checking Seal dependency cycles: {error}"
                ),
            )
        })?;
    let event_is_local = state
        .event_queries()
        .has_canonical_event(event.event_id.as_str())
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "read canonical Event while checking Seal dependency cycles: {error}"
            ))
        })?;
    if !event_is_local {
        let event_digest =
            arkret_identifiers::Hash::new(event.event_digest().map_err(|error| {
                AppError::new(
                    ErrorCode::SchemaViolation,
                    format!("federated Event digest failed: {error}"),
                )
            })?)
            .map_err(|error| {
                AppError::new(
                    ErrorCode::SchemaViolation,
                    format!("federated Event digest is not a canonical Move digest: {error}"),
                )
            })?;
        if relevant.iter().any(|seal| {
            seal.delta.contains(&event_digest) || seal.covered_event_digests.contains(&event_digest)
        }) {
            return Err(AppError::new(
                ErrorCode::SchemaViolation,
                "federated Event Seal prerequisite transitively covers the Event itself",
            ));
        }
    }
    crate::routing::events::event_log::governance_proof::accept_federated_event_seal_path(
        state, realm_id, &relevant,
    )
    .await?;
    for root in roots {
        if state
            .projections()
            .seal_by_id(&root)
            .map_err(|error| {
                AppError::internal(format!(
                    "read projected transported Seal prerequisite: {error}"
                ))
            })?
            .is_none()
        {
            return Err(AppError::new(
                ErrorCode::DependencyMissing,
                "federated Event referenced Seal was not projected",
            ));
        }
    }
    Ok(())
}

pub(crate) async fn submit_federation_events(
    state: &AppState,
    req: &Request,
    body_value: Value,
    res: &mut Response,
) {
    // The transport carries only RFC 9530 Content-Digest. Compute the Arkret
    // request digest internally for idempotency, replay, and audit records.
    let request_hash = match canonical::canonical_sha256(&body_value) {
        Ok(value) => value,
        Err(error) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "schema_violation",
                &format!("ak.peer.events.command.submit body is not canonical-hashable: {error}"),
            );
            return;
        }
    };
    let submit = match serde_json::from_value::<EventsSubmitFederationRequestBody>(body_value) {
        Ok(value) => value,
        Err(error) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                &format!("invalid ak.peer.events.command.submit request body: {error}"),
            );
            return;
        }
    };
    let submit = match submit {
        EventsSubmitFederationRequestBody::Batch(batch) => batch,
        EventsSubmitFederationRequestBody::DirectConversationFounding(founding) => {
            submit_direct_conversation_federation(state, req, founding, request_hash, res).await;
            return;
        }
    };
    if let Err(error) = submit.validate_federation_transport() {
        tracing::debug!(%error, "federation transport contract rejected");
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "schema_violation",
            &format!("invalid federation transport contract: {error}"),
        );
        return;
    }
    let arkret_models_collaboration::event_sync::EventsSubmitFederationBatchRequestBody {
        service_binding_ref,
        events: submissions,
        cba_proof_bundles,
        signer_key_evidence,
        agent_signer_evidence_bundle,
    } = submit;
    // The federation rail no longer carries a bare `seals[]`: Seal
    // prerequisites are disclosed inside receiver-relative CBA proof bundles,
    // which MAY overlap, so the flat prerequisite list is the deduplicated
    // union in (notary_seq, id) order (`event_sync.rs::transported_seals`).
    let seals = {
        let mut seen = BTreeSet::new();
        let mut out: Vec<arkret_wire::Seal> = Vec::new();
        for bundle in &cba_proof_bundles {
            for seal in &bundle.seals {
                if seen.insert(seal.id.clone()) {
                    out.push(seal.clone());
                }
            }
        }
        out.sort_by(|left, right| {
            (left.notary_seq, left.id.as_str()).cmp(&(right.notary_seq, right.id.as_str()))
        });
        out
    };
    // Each transported Event travels with its authorization lease and the
    // ingress receipts that authorized its first publication
    // (`offline-publication.md` §2.1). The receipts are transport evidence:
    // they never enter the Event digest and MUST NOT be re-stamped here. Keyed
    // by Event id so the accept loop below can persist them verbatim once the
    // Event itself is accepted.
    let inbound_publication_evidence: BTreeMap<String, InboundPublicationEvidence> = submissions
        .iter()
        .filter_map(|submission| {
            let event_digest = submission.event.event_digest().ok()?;
            Some((
                submission.event.event_id.as_str().to_owned(),
                InboundPublicationEvidence {
                    event_digest,
                    realm_id: submission.event.realm_id.as_str().to_owned(),
                    authorization_lease: submission.authorization_lease.clone()?,
                    ingress_receipts: submission.ingress_receipts.clone(),
                },
            ))
        })
        .collect();
    let inbound_control_proposal_acks: BTreeMap<String, arkret_wire::ControlProposalAck> =
        submissions
            .iter()
            .filter_map(|submission| {
                submission
                    .control_proposal_ack
                    .clone()
                    .map(|receipt| (submission.event.event_id.as_str().to_owned(), receipt))
            })
            .collect();
    let events: Vec<arkret_wire::Event> = submissions
        .iter()
        .map(|submission| submission.event.clone())
        .collect();
    if events
        .first()
        .is_some_and(|event| event.kind == arkret_wire::EventKind::RealmCreate)
    {
        let leases = submissions
            .iter()
            .filter_map(|submission| submission.authorization_lease.clone())
            .collect::<Vec<_>>();
        if !leases.is_empty() && leases.len() != submissions.len() {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "a federated anchor unit cannot mix online and delayed submissions",
            );
            return;
        }
        if !leases.is_empty()
            && let Err(error) = arkret_wire::validate_anchor_unit_lease_bindings(&events, &leases)
        {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "schema_violation",
                &format!("federated anchor-unit publication evidence is invalid: {error}"),
            );
            return;
        }
    }
    for submission in &submissions {
        if let Some(lease) = &submission.authorization_lease
            && let Err(error) =
                validate_authorization_lease_for_event(state, None, &submission.event, lease).await
        {
            render_error(res, error.status, &error.code, &error.message);
            return;
        }
        if let Err(error) =
            validate_ingress_receipt_proofs(state, &submission.ingress_receipts).await
        {
            render_error(res, error.status, &error.code, &error.message);
            return;
        }
    }
    let mut verified_device_generations = BTreeMap::<(String, String), String>::new();
    for evidence in &signer_key_evidence {
        match super::validate_federated_device_signing_key_evidence(state, evidence).await {
            Ok(generation_ref) => {
                verified_device_generations.insert(
                    (
                        evidence.actor_id.to_string(),
                        evidence.device_id.to_string(),
                    ),
                    generation_ref,
                );
            }
            Err(error) => {
                tracing::debug!(%error, "federated device authorization evidence rejected");
                render_error(
                    res,
                    StatusCode::BAD_REQUEST,
                    "invalid_proof",
                    "federation signer_key_evidence has no valid portable device authorization",
                );
                return;
            }
        }
    }
    let mut verified_agent_signer_evidence = Vec::new();
    if let Some(bundle) = &agent_signer_evidence_bundle {
        for evidence in &bundle.evidence {
            let admission_evidence = match evidence {
                arkret_models_identity::agent_signer_evidence::AgentSignerEvidence::CurrentAdmission {
                    admission_evidence,
                    ..
                }
                | arkret_models_identity::agent_signer_evidence::AgentSignerEvidence::HistoricalEvent {
                    admission_evidence,
                    ..
                } => admission_evidence,
            };
            let binding = &admission_evidence
                .agent_authority_snapshot
                .core
                .signing_key_binding;
            let Some(event) = events.iter().find(|event| {
                event.applet_id.is_none()
                    && event
                        .executed_by
                        .as_ref()
                        .unwrap_or(&event.actor_id)
                        .as_str()
                        == binding.agent_id.as_str()
                    && event.proofs.iter().any(|proof| {
                        proof.verification_method == binding.verification_method.as_str()
                    })
            }) else {
                render_error(
                    res,
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    "federation Agent signer evidence does not match an Event",
                );
                return;
            };
            let public_key =
                match crate::routing::identity::agents::evidence::verify_federated_signer_evidence(
                    state,
                    evidence,
                    event,
                    now(),
                )
                .await
                {
                    Ok(public_key) => public_key,
                    Err(error) => {
                        tracing::debug!(%error, "federated Agent signer evidence rejected");
                        render_error(
                            res,
                            StatusCode::BAD_REQUEST,
                            "invalid_proof",
                            "federation Agent signer evidence is not independently verifiable",
                        );
                        return;
                    }
                };
            verified_agent_signer_evidence.push(VerifiedFederatedAgentSignerEvidence {
                agent_id: binding.agent_id.clone(),
                verification_method: binding.verification_method.clone(),
                public_key,
            });
        }
    }

    let trust_headers =
        match crate::routing::federation::federation::FederationTrustHeaders::from_salvo_request(
            req,
        ) {
            Ok(headers) => headers,
            Err(violation) => {
                render_error(
                    res,
                    StatusCode::BAD_REQUEST,
                    violation.error_code(),
                    &violation.message(),
                );
                return;
            }
        };
    let expected_destination = state.config().trust_domain.clone();
    if trust_headers
        .verify_destination(&expected_destination)
        .is_err()
    {
        render_error(
            res,
            StatusCode::CONFLICT,
            "cross_domain_replay_rejected",
            "federation Destination-Trust-Domain header does not match this service",
        );
        return;
    }
    if let Err((code, message)) =
        SolandEventsSubmitRequestBody::validate_federation_service_binding(&service_binding_ref)
    {
        render_error(res, StatusCode::BAD_REQUEST, code, &message);
        return;
    }
    if events.is_empty() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "ak.peer.events.command.submit must contain at least one event",
        );
        return;
    }
    if arkret_wire::event_envelope::validate_event_submit_batch_count(events.len()).is_err() {
        render_error(
            res,
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "ak.peer.events.command.submit exceeds max batch size",
        );
        return;
    }
    let events = match events
        .into_iter()
        .map(typed_event_to_canonical_value)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(events) => events,
        Err(error) => {
            render_submit_one_error(res, error);
            return;
        }
    };

    let binding_realm = service_binding_ref.realm_id.as_str().to_owned();
    let source_service_id = req
        .headers()
        .get("source-service-id")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or_default()
        .to_owned();
    match crate::routing::federation::frontier_exchange::inbound_peer_is_stale(
        state,
        &binding_realm,
        &source_service_id,
    )
    .await
    {
        Ok(true) => {
            let quarantine = events
                .iter()
                .filter_map(|envelope| event_string_field_from_value(envelope, "event_id"))
                .collect::<Vec<_>>();
            append_audit_log(
                state,
                None,
                "peer.events.submit",
                json!({
                    "realm_id": binding_realm,
                    "source_service_id": source_service_id,
                    "reason": "stale_peer",
                    "quarantine_count": quarantine.len()
                }),
                "quarantine",
            )
            .await;
            res.render(Json(events_submit_outcome(
                EventsSubmitStatus::Partial,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                quarantine,
                Some(super::super::sync::sync_token_for_state(state).await),
            )));
            return;
        }
        Ok(false) => {}
        Err(error) => {
            append_audit_log(
                state,
                None,
                "peer.events.submit",
                json!({
                    "realm_id": binding_realm,
                    "source_service_id": source_service_id,
                    "reason": "stale_peer_state_unavailable",
                    "error": error
                }),
                "reject",
            )
            .await;
            render_error(
                res,
                StatusCode::SERVICE_UNAVAILABLE,
                "stale_peer_state_unavailable",
                "federation stale_peer state is unavailable",
            );
            return;
        }
    }
    match federation_service_binding_current_for_destination(state, &service_binding_ref).await {
        FederationServiceBindingCheck::Current => {}
        FederationServiceBindingCheck::Reject(reason) => {
            render_error(res, StatusCode::CONFLICT, reason, reason);
            return;
        }
        FederationServiceBindingCheck::Stale(evidence) => {
            res.status_code(StatusCode::CONFLICT);
            res.render(Json(
                crate::routing::federation::federation::delivery_binding_stale_response(
                    &evidence.new_recipient_service_id,
                    &evidence.actor_id,
                    evidence
                        .new_service_resolution
                        .as_ref()
                        .expect("stale evidence requires a verified route carrier"),
                    &evidence.handover_frontier,
                    evidence.witness,
                ),
            ));
            return;
        }
        FederationServiceBindingCheck::HandedOver(evidence) => {
            res.status_code(StatusCode::CONFLICT);
            res.render(Json(
                crate::routing::federation::federation::delivery_binding_handed_over_response(
                    &evidence.new_recipient_service_id,
                ),
            ));
            return;
        }
    }
    let mut accepted = Vec::new();
    let mut duplicate = Vec::new();
    let mut rejected = Vec::new();
    let mut quarantine = Vec::new();
    let created_at = now();
    let source_trust_domain = trust_headers.source_trust_domain.as_str().to_owned();
    let profile_gate =
        match crate::routing::federation::federation::federation_profile_intersection_for_peer(
            state,
            &source_service_id,
            Some(&source_trust_domain),
        )
        .await
        {
            Ok(gate) => gate,
            Err(rejection) => {
                let rejected = events
                    .iter()
                    .map(|envelope| {
                        rejected_item(
                            event_string_field_from_value(envelope, "event_id")
                                .unwrap_or_else(|| "unknown".to_owned()),
                            ReasonCode::from_wire(rejection.code),
                            Some(rejection.message.clone()),
                        )
                    })
                    .collect::<Vec<_>>();
                append_audit_log(
                    state,
                    None,
                    "peer.events.submit",
                    json!({
                        "realm_id": binding_realm,
                        "source_trust_domain": source_trust_domain,
                        "source_service_id": source_service_id,
                        "request_canonical_digest": request_hash,
                        "accepted": Vec::<String>::new(),
                        "duplicate": Vec::<String>::new(),
                        "rejected_count": rejected.len(),
                        "quarantine_count": 0,
                        "reason": rejection.code,
                    }),
                    "partial",
                )
                .await;
                res.render(Json(events_submit_outcome(
                    EventsSubmitStatus::Partial,
                    Vec::new(),
                    Vec::new(),
                    rejected,
                    Vec::new(),
                    Some(super::super::sync::sync_token_for_state(state).await),
                )));
                return;
            }
        };

    if batch_begins_realm_create(&events) {
        let Some(actor) = events
            .first()
            .and_then(|event| event_string_field_from_value(event, "actor_id"))
        else {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "missing_param",
                "actor_id is required",
            );
            return;
        };
        let ordinary_origin =
            crate::routing::federation::federation::federation_actor_origin_acceptable(
                state,
                &actor,
                &source_service_id,
                &binding_realm,
                None,
            )
            .await;
        if !ordinary_origin
            && !direct_bootstrap_source_is_contact_authority(state, &source_service_id, &events)
                .await
        {
            render_error(
                res,
                StatusCode::FORBIDDEN,
                "capability_denied",
                "Realm bootstrap actor is not authorized for the source service",
            );
            return;
        }
        for event in &events {
            if let Err(rejection) = profile_gate.enforce_event(event) {
                render_error(
                    res,
                    StatusCode::BAD_REQUEST,
                    rejection.code,
                    &rejection.message,
                );
                return;
            }
        }
        let device_id = signer_key_evidence
            .iter()
            .find(|evidence| evidence.actor_id.as_str() == actor)
            .map(|evidence| evidence.device_id.to_string())
            .unwrap_or_else(|| format!("federation:{source_trust_domain}"));
        let session = SessionRecord {
            token_hash: format!("federation:{source_trust_domain}:{request_hash}"),
            actor: actor.clone(),
            device_id: device_id.clone(),
            audience: state.service_id().clone(),
            session_public_key: None,
            agent_session: None,
            session_grant: None,
            expires_at: created_at + Duration::minutes(5),
            created_at,
            revoked_at: None,
        };
        let admissions = events
            .iter()
            .map(|event| {
                InternalEventAdmission::peer_federated_event(
                    event_string_field_from_value(event, "realm_id").unwrap_or_default(),
                    actor.clone(),
                    device_id.clone(),
                    event_string_field_from_value(event, "event_id").unwrap_or_default(),
                    signer_key_evidence.clone(),
                    verified_agent_signer_evidence.clone(),
                )
            })
            .collect::<Vec<_>>();
        // Federation transports the origin's immutable publication evidence.
        // The leases above have already been structurally and cryptographically
        // verified against their Events; preserve them through the shared
        // bootstrap path so the destination does not try to mint replacement
        // Control Proposal Acks under its own (non-authoritative) service key.
        let authorization_leases = submissions
            .iter()
            .map(|submission| submission.authorization_lease.clone())
            .collect::<Vec<_>>();
        match submit_realm_bootstrap_batch(
            state,
            &session,
            events,
            Some(admissions.as_slice()),
            Some(authorization_leases.as_slice()),
            None,
        )
        .await
        {
            Ok(outcome) => {
                project_verified_federated_device_evidence(
                    state,
                    &signer_key_evidence,
                    &verified_device_generations,
                    &source_service_id,
                )
                .await;
                res.render(Json(outcome));
            }
            Err(error) if error.code == "dependency_missing" => render_error(
                res,
                StatusCode::CONFLICT,
                "dependency_missing",
                "the atomic Realm genesis unit is waiting for dependencies",
            ),
            Err(error) => render_submit_one_error(res, error),
        }
        return;
    }

    if !crate::routing::events::event_log::realm_is_indexed(state, &binding_realm)
        && events.iter().any(|event| {
            event_string_field_from_value(event, "kind").as_deref()
                != Some(arkret_wire::EventKind::InviteCreate.as_str())
        })
    {
        rejected.extend(events.iter().map(|event| {
            let mut item = rejected_item(
                event_string_field_from_value(event, "event_id")
                    .unwrap_or_else(|| "unknown".to_owned()),
                ReasonCode::DependencyMissing,
                Some("the referenced Realm bootstrap has not arrived yet".to_owned()),
            );
            item.missing_event_ids = service_binding_ref.membership_frontier.clone();
            item
        }));
        res.render(Json(events_submit_outcome(
            EventsSubmitStatus::Partial,
            Vec::new(),
            Vec::new(),
            rejected,
            Vec::new(),
            Some(super::super::sync::sync_token_for_state(state).await),
        )));
        return;
    }

    for envelope in events {
        let id = event_string_field_from_value(&envelope, "event_id")
            .unwrap_or_else(|| "unknown".to_owned());
        let event_realm = event_string_field_from_value(&envelope, "realm_id");
        if event_realm.as_deref() != Some(binding_realm.as_str()) {
            rejected.push(rejected_item(
                id,
                ReasonCode::from_wire("schema_violation"),
                Some("event realm_id must match service_binding_ref.realm_id".to_owned()),
            ));
            continue;
        }
        let Some(actor) = event_string_field_from_value(&envelope, "actor_id") else {
            rejected.push(rejected_item(
                id,
                ReasonCode::from_wire("missing_param"),
                Some("actor_id is required".to_owned()),
            ));
            continue;
        };
        if validate_did(&actor).is_err() {
            rejected.push(rejected_item(
                id,
                ReasonCode::from_wire("invalid_param"),
                Some("actor_id must be a DID".to_owned()),
            ));
            continue;
        }
        if let Err(rejection) = profile_gate.enforce_event(&envelope) {
            rejected.push(rejected_item(
                id,
                ReasonCode::from_wire(rejection.code),
                Some(rejection.message),
            ));
            continue;
        }
        let event_kind = event_string_field_from_value(&envelope, "kind");
        if event_string_field_from_value(&envelope, "kind").as_deref()
            == Some(arkret_wire::EventKind::MlsWelcome.as_str())
        {
            let Some(payload) = envelope.get("payload") else {
                rejected.push(rejected_item(
                    id,
                    ReasonCode::from_wire("schema_violation"),
                    Some("MLS Welcome payload is required".to_owned()),
                ));
                continue;
            };
            match crate::routing::mls::validate_federated_welcome_peer_claim(
                state,
                &source_service_id,
                &binding_realm,
                &actor,
                payload,
            )
            .await
            {
                Ok(()) => {}
                Err("peer_claim_welcome_pending") => {
                    let mut item = rejected_item(
                        id,
                        ReasonCode::DependencyMissing,
                        Some("the Welcome peer claim ledger entry is not available yet".to_owned()),
                    );
                    item.missing_event_ids =
                        serde_json::from_value::<arkret_wire::Event>(envelope.clone())
                            .map(|event| event.prev_refs)
                            .unwrap_or_default();
                    rejected.push(item);
                    continue;
                }
                Err(_) => {
                    rejected.push(rejected_item(
                        id,
                        ReasonCode::from_wire("failed_precondition"),
                        Some("MLS Welcome is not bound to the authenticated peer claim".to_owned()),
                    ));
                    continue;
                }
            }
        }
        // SOL-02-007 — bind the envelope actor to the authenticated source
        // service BEFORE constructing a session, instead of leaving author
        // identity entirely to the downstream proof chain. Two acceptance
        // paths:
        //   1. the actor DID and source service DID share their deployment authority; or
        //   2. the actor is already a member of the binding Realm in the local membership index
        //      (the source service is then relaying for a known member; identity is re-verified
        //      downstream by `validate_event_envelope`'s proof checks).
        if !crate::routing::federation::federation::federation_actor_origin_acceptable(
            state,
            &actor,
            &source_service_id,
            &binding_realm,
            event_kind.as_deref(),
        )
        .await
        {
            rejected.push(rejected_item(
                id,
                ReasonCode::from_wire("capability_denied"),
                Some("actor_id is not hosted by the source service authority and is not a known member of the binding realm".to_owned()),
            ));
            continue;
        }
        let device_id = event_string_field_from_value(&envelope, "device_id")
            .or_else(|| {
                signer_key_evidence
                    .iter()
                    .find(|evidence| evidence.actor_id.as_str() == actor)
                    .map(|evidence| evidence.device_id.to_string())
            })
            .unwrap_or_else(|| format!("federation:{source_trust_domain}"));
        let session = SessionRecord {
            token_hash: format!("federation:{source_trust_domain}:{}", request_hash),
            actor: actor.clone(),
            device_id: device_id.clone(),
            audience: state.service_id().clone(),
            session_public_key: None,
            agent_session: None,
            session_grant: None,
            expires_at: created_at + Duration::minutes(5),
            created_at,
            revoked_at: None,
        };
        let admission = InternalEventAdmission::peer_federated_event(
            binding_realm.clone(),
            actor.clone(),
            device_id,
            id.clone(),
            signer_key_evidence.clone(),
            verified_agent_signer_evidence.clone(),
        );
        let matching_device_evidence = signer_key_evidence
            .iter()
            .filter(|evidence| {
                evidence.actor_id.as_str() == actor
                    && envelope
                        .get("proofs")
                        .and_then(Value::as_array)
                        .is_some_and(|proofs| {
                            proofs.iter().any(|proof| {
                                proof.get("verification_method").and_then(Value::as_str)
                                    == Some(evidence.verification_method.as_str())
                            })
                        })
            })
            .cloned()
            .collect::<Vec<_>>();
        if let Err(error) = accept_federated_seal_prerequisite(
            state,
            &service_binding_ref.realm_id,
            &envelope,
            &seals,
        )
        .await
        {
            tracing::debug!(%error, event_id = %id, "federation Seal prerequisite is unavailable");
            let mut item = rejected_item(
                id,
                if error.code == ErrorCode::DependencyMissing {
                    ReasonCode::DependencyMissing
                } else {
                    ReasonCode::from_wire(error.wire_code())
                },
                Some(error.message.to_string()),
            );
            item.missing_seal_refs = if error.code == ErrorCode::DependencyMissing {
                serde_json::from_value::<arkret_wire::Event>(envelope.clone())
                    .ok()
                    .and_then(|event| event.seal_ref)
                    .into_iter()
                    .collect()
            } else {
                Vec::new()
            };
            rejected.push(item);
            continue;
        }
        match submit_event_value_with_context(
            state,
            &session,
            envelope.clone(),
            &[],
            None,
            Some(&admission),
            // No lease is handed to the local minting path: this Event was
            // already receipted by its origin ingress, and the transported
            // evidence is stored verbatim below instead.
            None,
            inbound_control_proposal_acks.get(&id),
            submissions
                .iter()
                .find(|submission| submission.event.event_id.as_str() == id)
                .and_then(|submission| submission.membership_compensation_evidence.as_ref()),
            None,
            false,
            None,
            &[],
            None,
        )
        .await
        {
            Ok(response) => {
                accepted.push(response.event_id.clone());
                if let Some(evidence) = inbound_publication_evidence.get(&response.event_id) {
                    store_inbound_publication_evidence(state, evidence).await;
                }
                if response.duplicate {
                    duplicate.push(response.event_id);
                }
                project_verified_federated_device_evidence(
                    state,
                    &matching_device_evidence,
                    &verified_device_generations,
                    &source_service_id,
                )
                .await;
            }
            Err(error) => {
                if error.code == "dependency_missing" {
                    let mut item = rejected_item(
                        id,
                        ReasonCode::DependencyMissing,
                        Some("a predecessor Event has not arrived yet".to_owned()),
                    );
                    item.missing_event_ids =
                        serde_json::from_value::<arkret_wire::Event>(envelope.clone())
                            .map(|event| event.prev_refs)
                            .unwrap_or_default();
                    rejected.push(item);
                    continue;
                }
                if let Some(event_id) = error.quarantine_event_id {
                    quarantine.push(event_id);
                } else {
                    rejected.push(rejected_item(
                        id,
                        ReasonCode::from_wire(&error.code),
                        Some(error.message),
                    ));
                }
            }
        }
    }

    let status = if !rejected.is_empty() || !quarantine.is_empty() {
        EventsSubmitStatus::Partial
    } else if accepted.len() == duplicate.len() && !duplicate.is_empty() {
        EventsSubmitStatus::Duplicate
    } else {
        EventsSubmitStatus::Accepted
    };
    let status_label = events_submit_status_label(status);
    append_audit_log(
        state,
        None,
        "peer.events.submit",
        json!({
            "realm_id": binding_realm,
            "source_trust_domain": source_trust_domain,
            "request_canonical_digest": request_hash,
            "accepted": accepted,
            "duplicate": duplicate,
            "rejected_count": rejected.len(),
            "quarantine_count": quarantine.len()
        }),
        status_label,
    )
    .await;
    res.render(Json(events_submit_outcome(
        status,
        accepted,
        duplicate,
        rejected,
        quarantine,
        Some(super::super::sync::sync_token_for_state(state).await),
    )));
}

async fn submit_direct_conversation_federation(
    state: &AppState,
    req: &Request,
    submission: arkret_models_collaboration::direct_conversation_ops::DirectConversationFoundingFederationSubmission,
    request_hash: String,
    res: &mut Response,
) {
    let receipt = &submission.source_acceptance_receipt;
    if let Err(error) = receipt.validate_shape() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            &error.to_string(),
        );
        return;
    }
    let events = submission
        .events
        .iter()
        .map(|item| &item.event)
        .collect::<Vec<_>>();
    let exact: [&arkret_wire::Event; 3] = events
        .try_into()
        .expect("typed founding federation carrier has exactly three Events");
    let plan = match DirectConversationFoundingPlan::from_events(exact) {
        Ok(plan) => plan,
        Err(error) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "direct_conversation_founding_unit_invalid",
                &error.to_string(),
            );
            return;
        }
    };
    if receipt.founder_id != submission.events[0].event.actor_id
        || receipt.realm_id != plan.realm_id
        || receipt.main_strand_id != plan.main_strand_id
        || receipt.founding_unit_digest != plan.founding_unit_digest
    {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "direct_conversation_founding_unit_invalid",
            "source receipt does not bind the transported founding unit",
        );
        return;
    }
    let source_service_id = req
        .headers()
        .get("source-service-id")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let source_service_id_typed = match arkret_wire::DidCoreId::new(source_service_id.to_owned()) {
        Ok(value) => value,
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "invalid Source-Service-ID",
            );
            return;
        }
    };
    let continuity_valid = verify_principal_service_binding_continuity(
        &submission.source_service_continuity,
        &source_service_id_typed,
        state,
    )
    .await
    .is_ok();
    if submission
        .source_service_continuity
        .accepted_binding
        .binding_digest
        != receipt.issuer_service_binding_digest
        || submission
            .source_service_continuity
            .accepted_binding
            .principal_id
            .as_str()
            != receipt.founder_id.as_str()
        || submission
            .source_service_continuity
            .accepted_binding
            .service_id
            != receipt.issuer_service_id
        || !continuity_valid
    {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "capability_denied",
            "transport source does not have valid founder service-binding continuity",
        );
        return;
    }
    let signing_input = match receipt.signing_input_bytes() {
        Ok(value) => value,
        Err(error) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "invalid_proof",
                &error.to_string(),
            );
            return;
        }
    };
    if let Err(error) = crate::jws_verify::verify_did_controlled_ed25519_signature_async(
        &signing_input,
        receipt.proof.jws.as_str(),
        receipt.proof.verification_method.as_str(),
        receipt.issuer_service_id.as_str(),
        state,
    )
    .await
    {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            &format!("founding acceptance receipt signature is invalid: {error}"),
        );
        return;
    }
    let peer_actor = submission.events[1]
        .event
        .payload
        .get("actor_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let destination = submission.events[1]
        .event
        .payload
        .get("delivery_binding")
        .and_then(Value::as_object)
        .and_then(|binding| binding.get("recipient_service_id"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if peer_actor.is_empty() || destination != state.service_id() {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "capability_denied",
            "founding destination does not carry the local peer participant",
        );
        return;
    }
    let envelopes = match submission
        .events
        .iter()
        .map(|item| typed_event_to_canonical_value(item.event.clone()))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(value) => value,
        Err(error) => {
            render_submit_one_error(res, error);
            return;
        }
    };
    if !direct_bootstrap_source_is_contact_authority(state, source_service_id, &envelopes).await {
        render_error(
            res,
            StatusCode::CONFLICT,
            "dependency_missing",
            "the Direct Conversation Contact basis mirror is not available",
        );
        return;
    }
    let mut verified_signers = Vec::new();
    for evidence in &submission.signer_key_evidence {
        if let Err(error) =
            super::validate_federated_device_signing_key_evidence(state, evidence).await
        {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "invalid_proof",
                &format!("founding signer evidence is invalid: {error}"),
            );
            return;
        }
        verified_signers.push(evidence.clone());
    }
    let created_at = now();
    let session = SessionRecord {
        token_hash: format!("federation:direct-conversation:{request_hash}"),
        actor: receipt.founder_id.to_string(),
        device_id: verified_signers
            .first()
            .map(|evidence| evidence.device_id.to_string())
            .unwrap_or_else(|| "federation:direct-conversation".to_owned()),
        audience: state.service_id().clone(),
        session_public_key: None,
        agent_session: None,
        session_grant: None,
        expires_at: created_at + Duration::minutes(5),
        created_at,
        revoked_at: None,
    };
    let admissions = submission
        .events
        .iter()
        .map(|item| {
            InternalEventAdmission::peer_federated_event(
                plan.realm_id.to_string(),
                receipt.founder_id.to_string(),
                session.device_id.clone(),
                item.event.event_id.to_string(),
                verified_signers.clone(),
                Vec::new(),
            )
        })
        .collect::<Vec<_>>();
    let leases = submission
        .events
        .iter()
        .map(|item| item.authorization_lease.clone())
        .collect::<Vec<_>>();
    match submit_realm_bootstrap_batch(
        state,
        &session,
        envelopes,
        Some(&admissions),
        Some(&leases),
        None,
    )
    .await
    {
        Ok(outcome) => res.render(Json(outcome)),
        Err(error) if error.code == "dependency_missing" => render_error(
            res,
            StatusCode::CONFLICT,
            "dependency_missing",
            "the atomic Direct Conversation founding unit is waiting for dependencies",
        ),
        Err(error) => render_submit_one_error(res, error),
    }
}

async fn verify_accepted_principal_service_binding(
    binding: &arkret_models_collaboration::direct_conversation_ops::AcceptedAtServiceBinding,
    state: &AppState,
) -> Result<(), String> {
    use arkret_models_collaboration::direct_conversation_ops::PrincipalServiceBindingProofPurpose;
    binding
        .validate_shape()
        .map_err(|error| error.to_string())?;
    let service_input = binding
        .proof_signing_input_bytes(
            PrincipalServiceBindingProofPurpose::ServiceAcceptance,
            &binding.service_acceptance_proof.verification_method,
        )
        .map_err(|error| error.to_string())?;
    crate::jws_verify::verify_did_controlled_ed25519_signature_with_public_key_async(
        &service_input,
        binding.service_acceptance_proof.jws.as_str(),
        binding
            .service_acceptance_proof
            .verification_method
            .as_str(),
        binding.service_id.as_str(),
        &binding.service_verification_method.public_key_multibase,
        state,
    )
    .await
    .map_err(|error| format!("service binding acceptance proof is invalid: {error}"))?;
    let principal_input = binding
        .proof_signing_input_bytes(
            PrincipalServiceBindingProofPurpose::PrincipalAuthorization,
            &binding.principal_authorization_proof.verification_method,
        )
        .map_err(|error| error.to_string())?;
    crate::jws_verify::verify_principal_authorized_ed25519_signature_async(
        &principal_input,
        binding.principal_authorization_proof.jws.as_str(),
        binding
            .principal_authorization_proof
            .verification_method
            .as_str(),
        binding.principal_id.as_str(),
        state,
    )
    .await
    .map_err(|error| error.to_string())
}

async fn verify_principal_service_binding_continuity(
    continuity: &arkret_models_collaboration::direct_conversation_ops::PrincipalServiceBindingContinuity,
    transport_source: &arkret_wire::DidCoreId,
    state: &AppState,
) -> Result<(), String> {
    continuity
        .validate_shape(transport_source)
        .map_err(|error| error.to_string())?;
    verify_accepted_principal_service_binding(&continuity.accepted_binding, state).await?;
    for edge in &continuity.cutovers {
        verify_accepted_principal_service_binding(&edge.new_binding, state).await?;
        let input = edge
            .signing_input_bytes()
            .map_err(|error| error.to_string())?;
        for (proof, issuer_core) in [
            (&edge.principal_proof, edge.principal_id.as_str()),
            (
                &edge.previous_service_proof,
                edge.previous_service_id.as_str(),
            ),
            (&edge.new_service_proof, edge.new_service_id.as_str()),
        ] {
            let issuer = arkret_identity::verification_method_did(&proof.verification_method)
                .map_err(|error| error.to_string())?;
            if arkret_wire::project_full_id_to_core_id(&issuer)
                .map_err(|error| error.to_string())?
                .as_str()
                != issuer_core
            {
                return Err(
                    "service-binding cutover proof controller does not project to issuer core_id"
                        .to_owned(),
                );
            }
            crate::jws_verify::verify_did_controlled_ed25519_signature_async(
                &input,
                proof.jws.as_str(),
                proof.verification_method.as_str(),
                issuer.as_str(),
                state,
            )
            .await?;
        }
    }
    Ok(())
}

async fn project_verified_federated_device_evidence(
    state: &AppState,
    evidence: &[arkret_wire::event_envelope::FederatedDeviceSigningKeyEvidence],
    generations: &BTreeMap<(String, String), String>,
    source_service_id: &str,
) {
    for entry in evidence {
        let key = (entry.actor_id.to_string(), entry.device_id.to_string());
        let Some(generation_ref) = generations.get(&key) else {
            continue;
        };
        if let Err(error) = super::project_federated_device_signing_key_evidence(
            state,
            entry,
            generation_ref,
            source_service_id,
        )
        .await
        {
            tracing::warn!(
                %error,
                actor_id = %entry.actor_id,
                device_id = %entry.device_id,
                "failed to project verified federated device authorization"
            );
        }
    }
}

pub(super) fn event_string_field_from_value(value: &Value, field: &str) -> Option<String> {
    value
        .as_object()
        .and_then(|object| event_string_field(object, &[field]))
}

/// Resolve an envelope's Realm id the way the SDK envelope type does.
///
/// `ak.realm.create` carries no wire `realm_id` (`zh/models/realm-and-space.md`
/// section 2.5.0) — the id is derived from the genesis Event itself, and an
/// envelope that does carry one is rejected upstream with the common
/// `object_id_not_event_derived` reason. A flat `realm_id` read is therefore *always*
/// `None` on a genesis create, so every caller that needs a Realm id for a batch
/// that may begin with one must go through this instead of
/// `event_string_field_from_value(.., "realm_id")`.
pub(super) fn event_realm_id_from_value(value: &Value) -> Option<String> {
    if let Some(realm_id) = event_string_field_from_value(value, "realm_id") {
        return Some(realm_id);
    }
    if event_string_field_from_value(value, "kind").as_deref()
        != Some(arkret_wire::EventKind::RealmCreate.as_str())
    {
        return None;
    }
    let event_id =
        arkret_wire::EventId::new(event_string_field_from_value(value, "event_id")?).ok()?;
    Some(arkret_wire::derive_genesis_realm_id(&event_id).into_string())
}

mod delivery_binding;
mod ingress_receipt;
mod outcome;
mod post_commit;
mod preflight;
mod value;

use delivery_binding::*;
pub(in crate::routing) use ingress_receipt::validate_authorization_lease_for_event;
use ingress_receipt::*;
pub(super) use outcome::events_submit_outcome;
use outcome::*;
use post_commit::*;
use preflight::*;
use value::*;
pub(in crate::routing::events::event_log) use value::{
    self_principal_pcr_control_authority_rejection, submit_event_value_with_idempotency,
};
pub(in crate::routing) use value::{
    submit_account_data_event_value, submit_event_value, submit_initial_event_submission,
    submit_initial_event_submission_with_contact_projection,
    submit_initial_event_submission_with_device_pairing, submit_mimi_event_value,
    submit_mimi_moderation_report_event_value,
};
// `submit_one_error_to_app_error` is defined in this module, so it needs no
// re-export here; `event_log.rs` names it directly.

#[cfg(test)]
mod received_at_stamp_tests {
    use super::*;

    fn operation_for_kind(kind: impl AsRef<str>, suffix: u32) -> Operation {
        arkret_event_draft::test_support::raw_projected_operation(
            OperationId::new(format!(
                "ak:operation:01904100-0000-7000-8000-{suffix:012x}"
            ))
            .unwrap(),
            RealmId::new("ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K".to_owned())
                .unwrap(),
            kind.as_ref(),
            json!({ "actor_id": "did:web:alice.example" }),
        )
    }

    #[test]
    fn received_at_stamp_only_mutates_membership_projection_payloads() {
        let received_at = DateTime::parse_from_rfc3339("2026-07-07T05:20:58.398662Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut device_authorize = operation_for_kind("ak.device.authorize", 1);
        let mut member_state = operation_for_kind(arkret_wire::EventKind::MemberState, 2);
        let mut circle_member_state =
            operation_for_kind(arkret_wire::EventKind::CircleMemberState, 3);

        stamp_projection_operation_received_at(&mut device_authorize, received_at);
        stamp_projection_operation_received_at(&mut member_state, received_at);
        stamp_projection_operation_received_at(&mut circle_member_state, received_at);

        assert!(device_authorize.payload.get("event_received_at").is_none());
        assert_eq!(
            member_state
                .payload
                .get("event_received_at")
                .and_then(Value::as_str),
            Some("2026-07-07T05:20:58.398Z")
        );
        assert_eq!(
            circle_member_state
                .payload
                .get("event_received_at")
                .and_then(Value::as_str),
            Some("2026-07-07T05:20:58.398Z")
        );
    }
}

#[cfg(test)]
mod managed_agent_pcr_batch_tests {
    use super::*;

    fn managed_agent_create_value() -> Value {
        let realm_id =
            RealmId::new("ak:realm:AZiVojGkhKKjoBSA6eV96sZAm4u3Ze_3uMmkr30F6ZQZ".to_owned())
                .unwrap();
        let agent_id =
            arkret_identifiers::DidFullId::new("did:web:agent.example".to_owned()).unwrap();
        let agent_actor_id = arkret_wire::project_full_id_to_core_id(&agent_id).unwrap();
        let genesis =
            arkret_models_collaboration::events_payloads::RealmGenesis::managed_agent_control(
                arkret_wire::GenesisSalt::new(
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                )
                .unwrap(),
                arkret_identifiers::TypedTrustDomainId::new(
                    "ak:trust_domain:managed-agent-pcr".to_owned(),
                )
                .unwrap(),
                vec!["ak.profile.principal_control_realm.v1".to_owned()],
                arkret_wire::CORE_REDUCER_PROFILE,
                arkret_canonical::DigestSuite::Sha256,
                arkret_wire::SecurityClass::HighAssurance,
                arkret_wire::EncryptionProfile::MlsRfc9420,
                arkret_models_collaboration::objects::realm::NotaryProfile::SingleDid,
                arkret_wire::notary::NotaryValue::single_did(agent_actor_id.clone()),
                arkret_policy::current_capability_action_registry_digest().unwrap(),
            )
            .unwrap();
        let payload =
            arkret_models_collaboration::events_payloads::RealmCreatePayload::new(genesis)
                .to_value()
                .unwrap();
        let mut event = arkret_wire::test_support::raw_event(
            arkret_wire::EventKind::RealmCreate.as_str(),
            arkret_wire::ScopeRef::Realm { realm_id },
            agent_actor_id,
            0,
            arkret_identifiers::Hlc::new("01980b44cc00-0000-aabbcce1".to_owned()).unwrap(),
            payload,
        )
        .unwrap();
        event.executed_by = Some(crate::test_actor_id_str("did:web:alice.example"));
        event.authorization_ref = Some(
            arkret_wire::AuthorizationRef::new("did:web:agent.example#managed-controller").unwrap(),
        );
        event.refs.clear();
        // v1 carries no producer `effects[]`: the router recognises a managed
        // Agent PCR create by whether the registered contract materializes its
        // control material, so the fixture is the bare signed Event.
        serde_json::to_value(event).unwrap()
    }

    #[test]
    fn delegated_managed_agent_create_bypasses_ordinary_bootstrap_router() {
        assert!(batch_is_managed_agent_pcr_create(&[
            managed_agent_create_value()
        ]));
    }

    #[test]
    fn ordinary_or_multi_event_create_stays_on_ordinary_bootstrap_router() {
        let mut ordinary = managed_agent_create_value();
        ordinary.as_object_mut().unwrap().remove("executed_by");
        assert!(!batch_is_managed_agent_pcr_create(&[ordinary]));

        let managed = managed_agent_create_value();
        assert!(!batch_is_managed_agent_pcr_create(&[
            managed.clone(),
            managed,
        ]));
    }
}

#[cfg(test)]
mod internal_event_admission_tests {
    use super::*;

    fn internal_session(actor: &str, device_id: &str) -> SessionRecord {
        let now = Utc::now();
        SessionRecord {
            token_hash: "internal-session".to_owned(),
            actor: actor.to_owned(),
            device_id: device_id.to_owned(),
            audience: "soland".to_owned(),
            session_public_key: None,
            agent_session: None,
            session_grant: None,
            expires_at: now + Duration::minutes(5),
            created_at: now,
            revoked_at: None,
        }
    }

    fn mimi_session() -> SessionRecord {
        internal_session("did:web:mimi.example", "mimi-provider-facade")
    }

    #[test]
    fn mimi_provider_admission_reads_provenance_from_canonical_metadata() {
        let admission = InternalEventAdmission::mimi_provider(
            "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K",
            "did:web:mimi.example",
            "ak:mimi-binding:01904100-0000-7000-8000-000000000001",
        );
        let object = json!({
            "actor_id": "did:web:mimi.example",
            "realm_id": "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K",
            "kind": "ak.message.create",
            "payload": {
                "metadata": {
                    "mimi_provenance": {
                        "mimi_room_binding_ref": "ak:mimi-binding:01904100-0000-7000-8000-000000000001"
                    }
                }
            }
        });

        assert!(admission.matches(&mimi_session(), object.as_object().unwrap()));
    }
}

#[cfg(test)]
mod federation_delivery_binding_tests {
    use super::*;

    fn event_id(suffix: u32) -> EventId {
        let digest = Hash::new(arkret_canonical::sha256_digest(suffix.to_be_bytes())).unwrap();
        EventId::from_event_digest(&digest).unwrap()
    }

    fn member_view(
        actor: &str,
        recipient_service_id: &str,
        frontier: &EventId,
        updated_at: DateTime<Utc>,
    ) -> DeliveryBindingMemberView {
        DeliveryBindingMemberView {
            member: actor.to_owned(),
            realm_id: "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K".to_owned(),
            recipient_service_id: recipient_service_id.to_owned(),
            membership_event_ref: Some(frontier.as_str().to_owned()),
            delivery_binding_frontier_ref: frontier.as_str().to_owned(),
            updated_at,
        }
    }

    #[test]
    fn federation_service_binding_check_accepts_current_local_frontier() {
        let now = Utc::now();
        let frontier = event_id(1);
        let result = federation_service_binding_check_from_members(
            "did:web:local.example",
            now,
            std::slice::from_ref(&frontier),
            vec![member_view(
                "did:web:alice.example",
                "did:web:local.example",
                &frontier,
                now,
            )],
        );

        assert!(matches!(result, FederationServiceBindingCheck::Current));
    }

    #[test]
    fn realm_sync_endpoint_binding_requires_declared_destination_and_policy_bundle_frontier() {
        let policy_bundle_event_id = event_id(1);
        let binding = FederationServiceBindingRef {
            realm_id: RealmId::new("ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K")
                .unwrap(),
            realm_policy_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            membership_frontier: vec![policy_bundle_event_id.clone()],
            delivery_binding_frontier: vec![policy_bundle_event_id.clone()],
            destination_service_kind: "principal_server".to_owned(),
        };
        let policy_bundle_envelope = json!({
            "payload": {
                "policy_revision": 1,
                "sync_endpoints": [{
                    "did": "did:web:mirror.example",
                    "endpoint": "https://mirror.example",
                    "role": "mirror",
                    "service_kind": "principal_server",
                    "plaintext_visible": true,
                    "visibility_scope": "plaintext_events"
                }]
            }
        });

        assert!(realm_sync_endpoint_authorizes_destination(
            "did:web:mirror.example",
            &binding,
            policy_bundle_event_id.as_str(),
            &policy_bundle_envelope,
        ));
        assert!(!realm_sync_endpoint_authorizes_destination(
            "did:web:other.example",
            &binding,
            policy_bundle_event_id.as_str(),
            &policy_bundle_envelope,
        ));

        let mut stale_binding = binding;
        stale_binding.delivery_binding_frontier = vec![event_id(2)];
        assert!(!realm_sync_endpoint_authorizes_destination(
            "did:web:mirror.example",
            &stale_binding,
            policy_bundle_event_id.as_str(),
            &policy_bundle_envelope,
        ));
    }

    #[test]
    fn federation_service_binding_check_rejects_empty_frontier_as_schema_violation() {
        let now = Utc::now();
        let result = federation_service_binding_check_from_members(
            "did:web:local.example",
            now,
            &[],
            vec![member_view(
                "did:web:alice.example",
                "did:web:local.example",
                &event_id(1),
                now,
            )],
        );

        assert!(matches!(
            result,
            FederationServiceBindingCheck::Reject("schema_violation")
        ));
    }

    #[test]
    fn federation_service_binding_check_emits_stale_handover_before_grace_expires() {
        let now = Utc::now();
        let old_frontier = event_id(1);
        let new_frontier = event_id(2);
        let result = federation_service_binding_check_from_members(
            "did:web:old.example",
            now,
            std::slice::from_ref(&old_frontier),
            vec![member_view(
                "did:web:alice.example",
                "did:web:new.example",
                &new_frontier,
                now - Duration::seconds(60),
            )],
        );

        match result {
            FederationServiceBindingCheck::Stale(evidence) => {
                assert_eq!(
                    evidence.new_recipient_service_id.as_str(),
                    "did:web:new.example"
                );
                assert_eq!(evidence.actor_id.as_str(), "did:web:alice.example");
                assert_eq!(evidence.handover_frontier, vec![new_frontier]);
            }
            other => panic!("expected stale handover evidence, got {other:?}"),
        }
    }

    #[test]
    fn federation_service_binding_check_emits_handed_over_after_grace_expires() {
        let now = Utc::now();
        let result = federation_service_binding_check_from_members(
            "did:web:old.example",
            now,
            &[event_id(1)],
            vec![member_view(
                "did:web:alice.example",
                "did:web:new.example",
                &event_id(2),
                now - Duration::seconds(DELIVERY_BINDING_HANDOVER_GRACE_SECONDS + 1),
            )],
        );

        assert!(matches!(
            result,
            FederationServiceBindingCheck::HandedOver(_)
        ));
    }

    #[test]
    fn federation_service_binding_check_rejects_ambiguous_handover_targets() {
        let now = Utc::now();
        let result = federation_service_binding_check_from_members(
            "did:web:old.example",
            now,
            &[event_id(1)],
            vec![
                member_view(
                    "did:web:alice.example",
                    "did:web:new.example",
                    &event_id(2),
                    now,
                ),
                member_view(
                    "did:web:bob.example",
                    "did:web:other.example",
                    &event_id(3),
                    now,
                ),
            ],
        );

        assert!(matches!(
            result,
            FederationServiceBindingCheck::Reject("delivery_binding_stale")
        ));
    }
}
