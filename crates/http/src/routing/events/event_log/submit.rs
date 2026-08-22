use std::collections::{BTreeMap, BTreeSet};
use std::hash::Hasher;
use std::sync::{Arc, OnceLock};

use arkret_event_draft::EventPayloadExt as _;
use arkret_models_collaboration::event_sync::EventsSubmitFederationRequestBody;
use arkret_models_collaboration::http_bodies::EventsSubmitRejectedRow;
use arkret_wire::ReasonCode;
use ed25519_dalek::Signer as _;
use soland_storage::ConflictCode;

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
const AGENT_MEMBERSHIP_CASCADE_LOCK_SHARDS: usize = 256;
pub(super) const IDEMPOTENCY_KEY_TTL_SECONDS: i64 = 86_400;

/// Bind the SDK's online-self publication lane to the exact authenticated
/// principal authority context. Delayed publication is authorized by its
/// signed lease and peer publication by federation admission; neither may be
/// silently reclassified as an online request merely because an uploader has
/// a valid session.
pub(super) fn validate_initial_publication_session_context(
    session: &SessionRecord,
    submission: &arkret_wire::EventInitialSubmission,
) -> Result<(), SubmitOneError> {
    if submission.publication_lane() != arkret_wire::EventPublicationLane::OnlineSelf {
        return Ok(());
    }
    let request_principal = submission
        .event
        .executed_by
        .as_ref()
        .unwrap_or(&submission.event.actor_id)
        .clone();
    let request_authority = arkret_wire::PrincipalAuthorityKey::new(
        request_principal,
        submission.event.principal_server_id.clone(),
    );
    let session_principal =
        arkret_wire::DidCoreId::new(session.actor.clone()).map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("authenticated session principal is invalid: {error}"),
            )
        })?;
    let session_server =
        arkret_wire::DidCoreId::new(session.audience.clone()).map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("authenticated session audience is invalid: {error}"),
            )
        })?;
    let expected = arkret_wire::PrincipalAuthorityKey::new(session_principal, session_server);
    if request_authority != expected {
        return Err(SubmitOneError::new(
            StatusCode::FORBIDDEN,
            "actor_session_mismatch",
            "online Event principal/executor and principal_server_id must match the authenticated session authority",
        ));
    }
    if let Some(grant) = session.session_grant.as_ref() {
        match &grant.holder_binding {
            arkret_models_identity::SessionGrantHolderBinding::HumanDevice { device_binding } => {
                let selector = grant.device_binding.as_ref().ok_or_else(|| {
                    SubmitOneError::new(
                        StatusCode::UNAUTHORIZED,
                        "auth_expired",
                        "online human Event session omitted its device authorization selector",
                    )
                })?;
                if selector.device_id.as_str() != session.device_id
                    || device_binding != &session.device_id
                {
                    return Err(SubmitOneError::new(
                        StatusCode::UNAUTHORIZED,
                        "auth_expired",
                        "online human Event session device selector is inconsistent",
                    ));
                }
            }
            arkret_models_identity::SessionGrantHolderBinding::AgentRuntime {
                agent_id,
                device_id,
                ..
            } => {
                if agent_id.as_str() != session.actor || device_id.as_str() != session.device_id {
                    return Err(SubmitOneError::new(
                        StatusCode::UNAUTHORIZED,
                        "auth_expired",
                        "online Agent Event session binding is inconsistent",
                    ));
                }
            }
        }
    }
    Ok(())
}

static ACTOR_SUBMIT_LOCKS: OnceLock<Vec<Arc<tokio::sync::Mutex<()>>>> = OnceLock::new();
static ACCOUNT_DATA_SUBMIT_LOCKS: OnceLock<Vec<Arc<tokio::sync::Mutex<()>>>> = OnceLock::new();
static INVITE_LIFECYCLE_LOCKS: OnceLock<Vec<Arc<tokio::sync::Mutex<()>>>> = OnceLock::new();
static SERVICE_EVENT_AUTHORING_LOCK: OnceLock<Arc<tokio::sync::Mutex<()>>> = OnceLock::new();
static AGENT_MEMBERSHIP_CASCADE_LOCKS: OnceLock<Vec<Arc<tokio::sync::Mutex<()>>>> = OnceLock::new();

mod identity_anchor;
use identity_anchor::{
    PcrGenesisPins, batch_contains_identity_anchor, submit_identity_anchor_batch,
};
mod ghost_provision;
pub(in crate::routing) use ghost_provision::submit_ghost_provision_batch;
mod sidecar_ensure;
pub(crate) use sidecar_ensure::submit_sidecar_ensure_batch;
mod agent_membership_cascade;
pub(in crate::routing) use agent_membership_cascade::submit_agent_membership_cascade;
use agent_membership_cascade::submit_agent_membership_cascade_federation;
mod realm_bootstrap;
use realm_bootstrap::{batch_begins_realm_create, submit_realm_bootstrap_batch};

fn rejected_item(
    id: String,
    reason_code: ReasonCode,
    detail: Option<String>,
) -> EventsSubmitRejectedRow {
    EventsSubmitRejectedRow {
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

fn agent_membership_cascade_lock(realm_id: &str) -> Arc<tokio::sync::Mutex<()>> {
    use std::hash::Hash as _;

    let locks = AGENT_MEMBERSHIP_CASCADE_LOCKS.get_or_init(|| {
        (0..AGENT_MEMBERSHIP_CASCADE_LOCK_SHARDS)
            .map(|_| Arc::new(tokio::sync::Mutex::new(())))
            .collect()
    });
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    realm_id.hash(&mut hasher);
    locks[(hasher.finish() as usize) % AGENT_MEMBERSHIP_CASCADE_LOCK_SHARDS].clone()
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

fn is_managed_agent_pcr_create(event: &arkret_wire::Event) -> bool {
    event.kind == arkret_wire::EventKind::RealmCreate
        && event.executed_by.as_ref() != Some(&event.actor_id)
        && arkret_bootstrap::materialize_managed_agent_pcr_control(
            std::slice::from_ref(event),
            &genesis_cell_write_projector,
        )
        .is_ok()
}

fn batch_is_managed_agent_pcr_create(envelopes: &[Value]) -> bool {
    if envelopes.len() != 1 {
        return false;
    }
    let Ok(event) = serde_json::from_value::<arkret_wire::Event>(envelopes[0].clone()) else {
        return false;
    };
    is_managed_agent_pcr_create(&event)
}

#[derive(Debug)]
pub(in crate::routing) struct ValidatedEventEnvelope {
    pub(in crate::routing) event_id: EventId,
    pub(in crate::routing) actor_id: DidCoreId,
    /// Submitting device, absent for a deviceless service session.
    pub(in crate::routing) device_id: Option<DeviceId>,
    pub(in crate::routing) actor_seq: u64,
    pub(in crate::routing) realm_id: RealmId,
    pub(in crate::routing) kind: String,
    pub(in crate::routing) schema_id: String,
    pub(in crate::routing) prev_refs: Vec<EventId>,
    pub(in crate::routing) canonical_digest: String,
    pub(in crate::routing) digest_suite: arkret_canonical::DigestSuite,
    pub(in crate::routing) canonical_bytes: Vec<u8>,
    pub(in crate::routing) producer_signing_key: Option<arkret_wire::DidKey>,
}

impl ValidatedEventEnvelope {
    /// The submitting device, or `""` for a deviceless service session — the
    /// same empty-source spelling projection already fans out on.
    pub(in crate::routing) fn device_id_str(&self) -> &str {
        self.device_id.as_ref().map_or("", DeviceId::as_str)
    }
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
    record: AcceptedEvent,
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

    #[test]
    fn semantic_schema_violation_keeps_machine_reason_in_details() {
        let error = SubmitOneError::semantic_schema_violation("private_view_requires_account_data");

        assert_eq!(error.code, "schema_violation");
        assert_eq!(
            error
                .details
                .as_ref()
                .and_then(|details| details.get("reason_code"))
                .and_then(Value::as_str),
            Some("private_view_requires_account_data")
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
    /// This batch already passed the closed four-Event Direct Conversation
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
    AgentMembershipCascade {
        event_id: String,
        initiator_id: String,
    },
    PeerFederatedEvent {
        event_id: String,
        producer_verification_method: arkret_wire::DidUrl,
        producer_signing_key: arkret_wire::DidKey,
    },
    PeerAgentMembershipCascade {
        event_id: String,
        initiator_id: String,
        producer_verification_method: arkret_wire::DidUrl,
        producer_signing_key: arkret_wire::DidKey,
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
            device_id: String::new(),
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
            device_id: String::new(),
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
            device_id: String::new(),
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

    pub(in crate::routing) fn agent_membership_cascade(
        realm_id: impl Into<String>,
        actor_id: impl Into<String>,
        initiator_id: impl Into<String>,
        device_id: impl Into<String>,
        event_id: impl Into<String>,
    ) -> Self {
        let initiator_id = initiator_id.into();
        Self {
            realm_id: realm_id.into(),
            actor_id: actor_id.into(),
            session_actor_id: initiator_id.clone(),
            kind: arkret_wire::EventKind::MemberState.as_str().to_owned(),
            device_id: device_id.into(),
            binding: InternalEventBinding::AgentMembershipCascade {
                event_id: event_id.into(),
                initiator_id,
            },
        }
    }

    pub(in crate::routing) fn peer_federated_event(
        realm_id: impl Into<String>,
        actor_id: impl Into<String>,
        device_id: impl Into<String>,
        event_id: impl Into<String>,
        producer_verification_method: arkret_wire::DidUrl,
        producer_signing_key: arkret_wire::DidKey,
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
                producer_verification_method,
                producer_signing_key,
            },
        }
    }

    pub(in crate::routing) fn peer_agent_membership_cascade(
        realm_id: impl Into<String>,
        actor_id: impl Into<String>,
        initiator_id: impl Into<String>,
        device_id: impl Into<String>,
        event_id: impl Into<String>,
        producer_verification_method: arkret_wire::DidUrl,
        producer_signing_key: arkret_wire::DidKey,
    ) -> Self {
        let actor_id = actor_id.into();
        let initiator_id = initiator_id.into();
        Self {
            realm_id: realm_id.into(),
            session_actor_id: initiator_id.clone(),
            actor_id,
            kind: arkret_wire::EventKind::MemberState.as_str().to_owned(),
            device_id: device_id.into(),
            binding: InternalEventBinding::PeerAgentMembershipCascade {
                event_id: event_id.into(),
                initiator_id,
                producer_verification_method,
                producer_signing_key,
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
                        payload.get("holder_id").and_then(Value::as_str) == Some(owner.as_str())
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
                InternalEventBinding::AgentMembershipCascade {
                    event_id,
                    initiator_id,
                } => {
                    object.get("event_id").and_then(Value::as_str) == Some(event_id.as_str())
                        && object
                            .get("executed_by")
                            .and_then(Value::as_str)
                            .unwrap_or(self.actor_id.as_str())
                            == initiator_id
                }
                InternalEventBinding::PeerFederatedEvent { event_id, .. } => {
                    object.get("event_id").and_then(Value::as_str) == Some(event_id.as_str())
                }
                InternalEventBinding::PeerAgentMembershipCascade {
                    event_id,
                    initiator_id,
                    ..
                } => {
                    object.get("event_id").and_then(Value::as_str) == Some(event_id.as_str())
                        && object
                            .get("executed_by")
                            .and_then(Value::as_str)
                            .unwrap_or(self.actor_id.as_str())
                            == initiator_id
                }
            }
    }

    pub(in crate::routing::events::event_log) fn federated_producer_signing_key(
        &self,
        session: &SessionRecord,
        object: &serde_json::Map<String, Value>,
        verification_method: &str,
    ) -> Option<&arkret_wire::DidKey> {
        if !self.matches(session, object) {
            return None;
        }
        match &self.binding {
            InternalEventBinding::PeerFederatedEvent {
                producer_verification_method,
                producer_signing_key,
                ..
            } if producer_verification_method.as_str() == verification_method => {
                Some(producer_signing_key)
            }
            InternalEventBinding::PeerAgentMembershipCascade {
                producer_verification_method,
                producer_signing_key,
                ..
            } if producer_verification_method.as_str() == verification_method => {
                Some(producer_signing_key)
            }
            _ => None,
        }
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

    /// A registered operation-semantic rejection is always a schema violation
    /// at the top level, while its stable machine discriminator belongs in
    /// `error.details.reason_code`. Keeping this mapping here prevents each
    /// admission lane from silently flattening the reason back into prose.
    pub(in crate::routing) fn semantic_schema_violation(reason_code: &'static str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "schema_violation", reason_code).with_details(
            serde_json::json!({
                "reason_code": reason_code,
            }),
        )
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
        StatusCode::BAD_REQUEST => ErrorCode::ParamInvalid,
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

pub(in crate::routing) fn submit_initial_event_batch_outcome<'a>(
    state: &'a AppState,
    session: &'a SessionRecord,
    submissions: Vec<arkret_wire::EventInitialSubmission>,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<EventsSubmitOutcome, SubmitOneError>> + Send + 'a>,
> {
    Box::pin(submit_initial_event_batch_outcome_inner(
        state,
        session,
        submissions,
    ))
}

async fn submit_initial_event_batch_outcome_inner(
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
    let event_refs = typed_events.iter().collect::<Vec<_>>();
    let digest_suites = trusted_federated_event_digest_suites(state, &event_refs)
        .map_err(|error| SubmitOneError::new(StatusCode::BAD_REQUEST, "schema_violation", error))?;
    for (submission, digest_suite) in submissions.into_iter().zip(digest_suites.iter().copied()) {
        validate_initial_submission_in_context(&submission, submit_context, digest_suite)?;
        validate_initial_publication_session_context(session, &submission)?;
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
        arkret_wire::validate_anchor_unit_lease_bindings(
            &typed_events,
            &complete_leases,
            &digest_suites,
        )
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("anchor-unit publication evidence is invalid: {error}"),
            )
        })?;
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
    for event in &submission.events {
        validate_initial_publication_session_context(session, event)?;
    }
    let typed_events = submission
        .events
        .iter()
        .map(|submission| &submission.event)
        .collect::<Vec<_>>();
    let exact: [&arkret_wire::Event; 4] = typed_events
        .try_into()
        .expect("typed founding carrier has exactly four Events");
    let plan = DirectConversationFoundingPlan::from_events(exact).map_err(|error| {
        SubmitOneError::new(
            StatusCode::BAD_REQUEST,
            "direct_conversation_founding_unit_invalid",
            error.to_string(),
        )
    })?;
    let trust_domain_id = state.config().trust_domain.clone();
    let (pair_key, founder_id, authorization_core) = match &submission.founding_authority_evidence {
        evidence @ arkret_models_collaboration::direct_conversation_ops::DirectConversationFoundingAuthorityEvidence::Human { .. } => {
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
        arkret_models_collaboration::direct_conversation_ops::DirectConversationFoundingAuthorityEvidence::ControllerAgent {
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
            "only the founder derived from the root Contact round may submit this unit",
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
    match &submission.founding_authority_evidence {
        arkret_models_collaboration::direct_conversation_ops::DirectConversationFoundingAuthorityEvidence::Human {
            contact_round_evidence,
            ..
        } => {
            let ([left, right], _) = submission
                .founding_authority_evidence
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
            let evidence_heads = contact_round_evidence
                .current_proofs
                .iter()
                .map(|proof| proof.head_event_ref.as_str())
                .collect::<std::collections::BTreeSet<_>>();
            if current.contact_round_id.as_deref() != Some(contact_round_evidence.contact_round_id.as_str())
                || current_heads != evidence_heads
                || contact_round_evidence
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
        arkret_models_collaboration::direct_conversation_ops::DirectConversationFoundingAuthorityEvidence::ControllerAgent {
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
    let mut receipt = DirectConversationFoundingAcceptanceReceipt {
        pair_key: pair_key.clone(),
        founder_id: founder_id.clone(),
        realm_id: plan.realm_id.clone(),
        main_strand_id: plan.main_strand_id.clone(),
        founding_unit_digest: plan.founding_unit_digest.clone(),
        authorization_core,
        slot_committed: true,
        issuer_service_id,
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
    let contact_round_evidence = submission.founding_authority_evidence.clone();
    let ordinary_outcome = submit_realm_bootstrap_batch(
        state,
        session,
        envelopes,
        None,
        Some(&leases),
        Some(realm_bootstrap::DirectConversationFoundingCommitContext {
            slot,
            receipt: receipt.clone(),
            founding_authority_evidence: contact_round_evidence,
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
            "param_missing",
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
    let mut pending_delivery_count = 0_u32;
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

    // Batch-aware policy validators (`operations::policy_extra`) scan sibling
    // Operations, so derive the whole batch's Operations once up front instead
    // of letting each Event's admission lane see only its own.
    let batch_operations: Vec<arkret_event_draft::ProjectedEventOperation> = envelopes
        .iter()
        .filter_map(projection_operation_from_envelope)
        .collect();

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
            SubmitEventContext {
                realm_bootstrap_contexts: &realm_bootstrap_contexts,
                batch_operations: &batch_operations,
                authorization_lease: authorization_leases
                    .and_then(|leases| leases.get(index))
                    .and_then(Option::as_ref),
                control_proposal_ack: control_proposal_acks
                    .and_then(|acks| acks.get(index))
                    .and_then(Option::as_ref),
                membership_compensation_evidence: membership_compensation_evidence
                    .and_then(|evidence| evidence.get(index))
                    .and_then(Option::as_ref),
                ..SubmitEventContext::empty()
            },
            SubmitMode::Commit(SubmitCommitOptions::none()),
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
                pending_delivery_count =
                    pending_delivery_count.saturating_add(response.outcome.pending_delivery_count);
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
    outcome.pending_delivery_count = pending_delivery_count;
    outcome.delivery_state = if pending_delivery_count == 0 {
        arkret_models_collaboration::http_bodies::EventDeliveryState::Complete
    } else {
        arkret_models_collaboration::http_bodies::EventDeliveryState::Pending
    };
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
    let event_refs = submissions
        .iter()
        .map(|submission| &submission.event)
        .collect::<Vec<_>>();
    let digest_suites = trusted_federated_event_digest_suites(state, &event_refs)
        .map_err(|error| SubmitOneError::new(StatusCode::BAD_REQUEST, "schema_violation", error))?;
    for (submission, digest_suite) in submissions.iter().zip(digest_suites.iter().copied()) {
        validate_initial_submission_in_context(submission, submit_context, digest_suite)?;
        validate_initial_publication_session_context(session, submission)?;
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
    let outcome = existing_pcr_genesis_outcome(state, request, accepted_device_id)
        .await?
        .ok_or_else(|| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "accepted PCR genesis receipt is unavailable",
            )
        })?;
    Ok(outcome)
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
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<(), AppError> {
    let mut roots = Vec::new();
    if let Some(seal_ref) = envelope.get("seal_ref").and_then(Value::as_str) {
        roots.push(
            arkret_identifiers::SealId::new(seal_ref.to_owned())
                .map_err(|error| AppError::param_invalid(format!("invalid seal_ref: {error}")))?,
        );
    }
    if let Some(leaves) = envelope
        .get("seal_basis")
        .and_then(|basis| basis.get("leaves"))
        .and_then(Value::as_array)
    {
        for leaf in leaves {
            let leaf = leaf.as_str().ok_or_else(|| {
                AppError::param_invalid("seal_basis.leaves must contain Seal ids")
            })?;
            roots.push(
                arkret_identifiers::SealId::new(leaf.to_owned()).map_err(|error| {
                    AppError::param_invalid(format!("invalid seal_basis leaf: {error}"))
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
        let event_digest = arkret_identifiers::Hash::new(
            event
                .event_digest_with_digest_suite(digest_suite)
                .map_err(|error| {
                    AppError::new(
                        ErrorCode::SchemaViolation,
                        format!("federated Event digest failed: {error}"),
                    )
                })?,
        )
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

async fn verify_federated_event_admission(
    state: &AppState,
    event: &arkret_wire::Event,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<(arkret_wire::DidUrl, arkret_wire::DidKey), String> {
    event
        .validate_principal_server_admission_binding(digest_suite)
        .map_err(|error| error.to_string())?;
    let [
        arkret_wire::EventProof::Producer(producer),
        arkret_wire::EventProof::PrincipalServerAdmission(admission),
    ] = event.proofs.as_slice()
    else {
        return Err("accepted Event proof set is not closed".to_owned());
    };
    if event.actor_kind == Some(arkret_wire::EnvelopeActorKind::Agent)
        && (admission.producer_signer_resolution_evidence_ref.is_none()
            || admission
                .producer_signer_resolution_evidence_digest
                .is_none())
    {
        return Err(
            "Native Agent admission omitted its frozen producer signer evidence".to_owned(),
        );
    }
    let producer_multibase = admission
        .producer_signing_key
        .as_str()
        .strip_prefix("did:key:")
        .ok_or_else(|| "admitted producer key is not an Ed25519 did:key".to_owned())?;
    let producer_key = arkret_canonical::decode_ed25519_multibase(producer_multibase)
        .map_err(|error| format!("admitted producer key is invalid: {error}"))?;
    verify_federated_producer_event_proof(event, producer, &producer_key)?;
    let admission_bytes = admission
        .canonical_binding_bytes()
        .map_err(|error| error.to_string())?;
    crate::jws_verify::verify_did_controlled_jws_async(
        &admission_bytes,
        &admission.jws,
        admission.verification_method.as_str(),
        event.principal_server_id.as_str(),
        state,
    )
    .await?;
    Ok((
        producer.verification_method.clone(),
        admission.producer_signing_key.clone(),
    ))
}

pub(super) fn trusted_federated_event_digest_suites(
    state: &AppState,
    events: &[&arkret_wire::Event],
) -> Result<Vec<arkret_canonical::DigestSuite>, String> {
    let first = events
        .first()
        .copied()
        .ok_or_else(|| "federated Event unit is empty".to_owned())?;
    if events.iter().any(|event| event.realm_id != first.realm_id) {
        return Err("federated Event unit crosses Realm boundaries".to_owned());
    }
    if first.kind == arkret_wire::EventKind::RealmCreate {
        let genesis_live_digest_suite = arkret::declared_genesis_live_digest_suite(first)
            .map_err(|error| format!("federated Realm genesis digest suite is invalid: {error}"))?;
        Ok(events
            .iter()
            .enumerate()
            .map(|(index, _)| {
                if index == 0 {
                    arkret_canonical::DigestSuite::Sha256
                } else {
                    genesis_live_digest_suite
                }
            })
            .collect())
    } else {
        let digest_suite = state
            .projections()
            .realm_digest_suite(first.realm_id.as_str());
        Ok(vec![digest_suite; events.len()])
    }
}

pub(crate) fn accepted_event_digest_suites(
    events: &[arkret_wire::Event],
) -> Result<Vec<arkret_canonical::DigestSuite>, String> {
    events
        .iter()
        .map(|event| {
            arkret::signed_event_digest_claim(event)
                .and_then(|digest| digest.digest_suite().map_err(Into::into))
                .map_err(|error| {
                    format!(
                        "accepted Event {} has no valid frozen digest-suite claim: {error}",
                        event.event_id
                    )
                })
        })
        .collect()
}

/// Verify an admitted producer proof through the SDK's strict Event profile.
///
/// A generic detached-JWS verifier is insufficient here: it accepts protected
/// `kid`, while Event proofs use the closed protected-header shape and also
/// re-derive `event_digest` from the proof-less envelope bytes.
fn verify_federated_producer_event_proof(
    event: &arkret_wire::Event,
    producer: &arkret_wire::ProducerEventProof,
    producer_key: &[u8; 32],
) -> Result<(), String> {
    let envelope_bytes = arkret_signatures::EventProofBuilder::new()
        .envelope_bytes(event)
        .map_err(|error| format!("federated Event canonicalization failed: {error}"))?;
    arkret_signatures::verify_ed25519_detached_jws_proof(
        producer,
        &envelope_bytes,
        &event.actor_id,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: producer_key.to_vec(),
        },
    )
    .map_err(|error| format!("admitted producer signature is invalid: {error}"))
}

#[cfg(test)]
mod federated_producer_event_proof_tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::verify_federated_producer_event_proof;

    fn fixture_event() -> arkret_wire::Event {
        let actor = arkret_wire::DidFullId::new("did:web:alice.example".to_owned()).unwrap();
        let actor_id = arkret_wire::project_full_id_to_core_id(&actor).unwrap();
        let principal_server_id =
            arkret_wire::DidCoreId::new("ak:did_core:web:remote.example".to_owned()).unwrap();
        let verification_method = arkret_wire::DidUrl::new(format!(
            "{actor}#ak:device:01904100-0000-7000-8000-a11ce0000001"
        ))
        .unwrap();
        let created_at = chrono::Utc::now();
        let event = arkret_wire::test_support::raw_event_at(
            arkret_wire::EventKind::MessageCreate.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: arkret_wire::RealmId::new(
                    "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K".to_owned(),
                )
                .unwrap(),
            },
            actor_id,
            principal_server_id,
            1,
            arkret_wire::Hlc::new("019041000000-0000-00000000".to_owned()).unwrap(),
            serde_json::json!({
                "strand_id": "ak:strand:AR3ud0srmtpodQ47XfsVC4uD75mQDAGaKLEww6VGMZZC",
                "track_name": "discussion",
                "content": {"kind": "ak.content.text", "body": "strict proof", "format": "plain"}
            }),
            created_at,
        )
        .unwrap();
        let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
            [21_u8; 32],
            actor,
            verification_method.clone(),
        );
        let mut event = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
            event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        arkret_signatures::sign_event(
            &mut event,
            &signer,
            &verification_method,
            arkret_signatures::SignEventOptions::new().with_created_at(created_at),
        )
        .unwrap();
        event.into_event()
    }

    fn sign_with_protected_header(
        proof: &arkret_wire::ProducerEventProof,
        actor_id: &arkret_wire::DidCoreId,
        key: &SigningKey,
        header: serde_json::Value,
    ) -> String {
        let header = URL_SAFE_NO_PAD.encode(
            arkret_canonical::canonical_json_bytes(&header).expect("canonical protected header"),
        );
        let binding = proof
            .canonical_binding_bytes(actor_id)
            .expect("canonical Event proof binding");
        let signing_input = format!("{header}.{}", URL_SAFE_NO_PAD.encode(binding));
        format!(
            "{header}..{}",
            URL_SAFE_NO_PAD.encode(key.sign(signing_input.as_bytes()).to_bytes())
        )
    }

    #[test]
    fn federated_producer_uses_strict_event_header_profile() {
        let event = fixture_event();
        let producer = event.proofs[0]
            .as_producer()
            .expect("fixture producer proof")
            .clone();
        let key = SigningKey::from_bytes(&[21_u8; 32]);

        verify_federated_producer_event_proof(&event, &producer, key.verifying_key().as_bytes())
            .expect("ordinary Event protected header verifies");

        let mut forbidden_kid = producer.clone();
        forbidden_kid.jws = sign_with_protected_header(
            &forbidden_kid,
            &event.actor_id,
            &key,
            serde_json::json!({
                "alg": "Ed25519",
                "kid": forbidden_kid.verification_method.as_str()
            }),
        );
        verify_federated_producer_event_proof(
            &event,
            &forbidden_kid,
            key.verifying_key().as_bytes(),
        )
        .expect_err("Event protected headers must reject kid even with a valid signature");
    }
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
                "json_invalid",
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
        EventsSubmitFederationRequestBody::AgentMembershipCascade(cascade) => {
            submit_agent_membership_cascade_federation(state, req, cascade, request_hash, res)
                .await;
            return;
        }
    };
    let transport_events = submit.transported_events().collect::<Vec<_>>();
    let digest_suites = match trusted_federated_event_digest_suites(state, &transport_events) {
        Ok(value) => value,
        Err(error) => {
            render_error(res, StatusCode::BAD_REQUEST, "schema_violation", &error);
            return;
        }
    };
    if let Err(error) = submit.validate_federation_transport(&digest_suites) {
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
        .zip(digest_suites.iter().copied())
        .filter_map(|(submission, digest_suite)| {
            let event_digest = submission
                .event
                .event_digest_with_digest_suite(digest_suite)
                .ok()?;
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
    let mut admitted_producers = BTreeMap::new();
    for (event, digest_suite) in events.iter().zip(digest_suites.iter().copied()) {
        match verify_federated_event_admission(state, event, digest_suite).await {
            Ok((verification_method, signing_key)) => {
                admitted_producers.insert(
                    event.event_id.as_str().to_owned(),
                    (verification_method, signing_key),
                );
            }
            Err(error) => {
                tracing::debug!(%error, event_id = %event.event_id, "federated Event admission proof rejected");
                render_error(
                    res,
                    StatusCode::BAD_REQUEST,
                    "invalid_proof",
                    "federated Event does not carry a valid origin Principal Server admission proof",
                );
                return;
            }
        }
    }
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
            && let Err(error) =
                arkret_wire::validate_anchor_unit_lease_bindings(&events, &leases, &digest_suites)
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
            "param_missing",
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
                    "reason": "peer_stale",
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
                    "reason": "peer_state_stale_unavailable",
                    "error": error
                }),
                "reject",
            )
            .await;
            render_error(
                res,
                StatusCode::SERVICE_UNAVAILABLE,
                "peer_state_stale_unavailable",
                "federation peer_stale state is unavailable",
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
    let mut agent_event_admission_receipts = Vec::new();
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
                "param_missing",
                "actor_id is required",
            );
            return;
        };
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
        let device_id = events
            .first()
            .and_then(|event| event_string_field_from_value(event, "device_id"))
            .unwrap_or_default();
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
                let event_id = event_string_field_from_value(event, "event_id").unwrap_or_default();
                let (verification_method, signing_key) = admitted_producers
                    .get(&event_id)
                    .expect("every typed federated Event was admission-verified");
                InternalEventAdmission::peer_federated_event(
                    event_string_field_from_value(event, "realm_id").unwrap_or_default(),
                    actor.clone(),
                    device_id.clone(),
                    event_id,
                    verification_method.clone(),
                    signing_key.clone(),
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
                ReasonCode::from_wire("param_missing"),
                Some("actor_id is required".to_owned()),
            ));
            continue;
        };
        if arkret_wire::DidCoreId::new(actor.clone()).is_err() {
            rejected.push(rejected_item(
                id,
                ReasonCode::from_wire("param_invalid"),
                Some("actor_id must be a DID Core ID".to_owned()),
            ));
            continue;
        }
        let event_kind = event_string_field_from_value(&envelope, "kind");
        let Some(event_principal_server_id) =
            event_string_field_from_value(&envelope, "principal_server_id")
        else {
            rejected.push(rejected_item(
                id,
                ReasonCode::from_wire("missing_param"),
                Some("principal_server_id is required".to_owned()),
            ));
            continue;
        };
        if !crate::routing::federation::federation::federation_actor_origin_acceptable(
            state,
            &actor,
            &source_service_id,
            Some(&event_principal_server_id),
            &binding_realm,
            event_kind.as_deref(),
        )
        .await
        {
            rejected.push(rejected_item(
                id,
                ReasonCode::from_wire("capability_denied"),
                Some("actor is outside the authenticated source service authority".to_owned()),
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
        if event_kind.as_deref() == Some(arkret_wire::EventKind::MlsWelcome.as_str()) {
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
                    let missing_event_ids = submissions
                        .iter()
                        .find(|submission| submission.event.event_id.as_str() == id)
                        .map(|submission| submission.event.prev_refs.clone())
                        .unwrap_or_default();
                    let mut item = rejected_item(
                        id,
                        ReasonCode::DependencyMissing,
                        Some("the Welcome peer claim ledger entry is not available yet".to_owned()),
                    );
                    item.missing_event_ids = missing_event_ids;
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
        // Deviceless relayed submission, not a device named "federation:<domain>".
        let device_id = event_string_field_from_value(&envelope, "device_id").unwrap_or_default();
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
        let (producer_verification_method, producer_signing_key) = admitted_producers
            .get(&id)
            .expect("every typed federated Event was admission-verified");
        let admission = InternalEventAdmission::peer_federated_event(
            binding_realm.clone(),
            actor.clone(),
            device_id,
            id.clone(),
            producer_verification_method.clone(),
            producer_signing_key.clone(),
        );
        if let Err(error) = accept_federated_seal_prerequisite(
            state,
            &service_binding_ref.realm_id,
            &envelope,
            &seals,
            state
                .projections()
                .realm_digest_suite(service_binding_ref.realm_id.as_str()),
        )
        .await
        {
            tracing::debug!(%error, event_id = %id, "federation Seal prerequisite is unavailable");
            let missing_seal_refs = if error.code == ErrorCode::DependencyMissing {
                submissions
                    .iter()
                    .find(|submission| submission.event.event_id.as_str() == id)
                    .and_then(|submission| submission.event.seal_ref.clone())
                    .into_iter()
                    .collect()
            } else {
                Vec::new()
            };
            let mut item = rejected_item(
                id,
                if error.code == ErrorCode::DependencyMissing {
                    ReasonCode::DependencyMissing
                } else {
                    ReasonCode::from_wire(error.wire_code())
                },
                Some(error.message.to_string()),
            );
            item.missing_seal_refs = missing_seal_refs;
            rejected.push(item);
            continue;
        }
        let typed_event = submissions
            .iter()
            .find(|submission| submission.event.event_id.as_str() == id)
            .map(|submission| &submission.event)
            .expect("federation envelope came from the typed submission");
        let prepared_agent_receipt =
            match prepare_agent_event_admission_receipt(state, typed_event, created_at).await {
                Ok(receipt) => receipt,
                Err(error) => {
                    render_error(
                        res,
                        StatusCode::SERVICE_UNAVAILABLE,
                        "temporarily_unavailable",
                        &error,
                    );
                    return;
                }
            };
        let receipt_idempotency = prepared_agent_receipt
            .as_ref()
            .and_then(|prepared| prepared.idempotency.clone())
            .map(SubmitCommitIdempotency::Prepared);
        match submit_event_value_with_context(
            state,
            &session,
            envelope.clone(),
            SubmitEventContext {
                internal_admission: Some(&admission),
                // No lease is handed to the local minting path: this Event was
                // already receipted by its origin ingress, and the transported
                // evidence is stored verbatim below instead.
                control_proposal_ack: inbound_control_proposal_acks.get(&id),
                membership_compensation_evidence: submissions
                    .iter()
                    .find(|submission| submission.event.event_id.as_str() == id)
                    .and_then(|submission| submission.membership_compensation_evidence.as_ref()),
                ..SubmitEventContext::empty()
            },
            SubmitMode::Commit(SubmitCommitOptions {
                idempotency: receipt_idempotency,
                ..SubmitCommitOptions::none()
            }),
        )
        .await
        {
            Ok(response) => {
                if let Some(evidence) = inbound_publication_evidence.get(&response.event_id) {
                    store_inbound_publication_evidence(state, evidence).await;
                }
                match load_agent_event_admission_receipt(state, typed_event).await {
                    Ok(Some(receipt)) => agent_event_admission_receipts.push(receipt),
                    Ok(None) if prepared_agent_receipt.is_none() => {}
                    Ok(None) => {
                        render_error(
                            res,
                            StatusCode::SERVICE_UNAVAILABLE,
                            "temporarily_unavailable",
                            "accepted Native Agent Event is missing its atomic receipt",
                        );
                        return;
                    }
                    Err(error) => {
                        render_error(
                            res,
                            StatusCode::SERVICE_UNAVAILABLE,
                            "temporarily_unavailable",
                            &error,
                        );
                        return;
                    }
                }
                if response.duplicate {
                    duplicate.push(response.event_id);
                } else {
                    accepted.push(response.event_id);
                }
            }
            Err(error) => {
                if error.code == "dependency_missing" {
                    let missing_event_ids = submissions
                        .iter()
                        .find(|submission| submission.event.event_id.as_str() == id)
                        .map(|submission| submission.event.prev_refs.clone())
                        .unwrap_or_default();
                    let mut item = rejected_item(
                        id,
                        ReasonCode::DependencyMissing,
                        Some("a predecessor Event has not arrived yet".to_owned()),
                    );
                    item.missing_event_ids = missing_event_ids;
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
    let mut outcome = events_submit_outcome(
        status,
        accepted,
        duplicate,
        rejected,
        quarantine,
        Some(super::super::sync::sync_token_for_state(state).await),
    );
    outcome.agent_event_admission_receipts = agent_event_admission_receipts;
    res.render(Json(outcome));
}

struct PreparedAgentEventAdmissionReceipt {
    idempotency: Option<soland_services::events::IdempotentResponse>,
}

async fn prepare_agent_event_admission_receipt(
    state: &AppState,
    event: &arkret_wire::Event,
    accepted_at: chrono::DateTime<chrono::Utc>,
) -> Result<Option<PreparedAgentEventAdmissionReceipt>, String> {
    use arkret_models_identity::agent_signer_evidence::{
        AgentDetachedJws, AgentEventAdmissionReceipt,
    };

    if event.actor_kind != Some(arkret_wire::EnvelopeActorKind::Agent) {
        return Ok(None);
    }
    let Some(admission) = event.proofs.iter().find_map(|proof| match proof {
        arkret_wire::EventProof::PrincipalServerAdmission(value) => Some(value),
        arkret_wire::EventProof::Producer(_) => None,
    }) else {
        return Err("federated Event omitted its Principal Server admission proof".to_owned());
    };
    let (Some(producer_evidence_ref), Some(producer_evidence_digest)) = (
        admission.producer_signer_resolution_evidence_ref.clone(),
        admission.producer_signer_resolution_evidence_digest.clone(),
    ) else {
        return Ok(None);
    };
    let receiver_service_id = arkret_wire::DidCoreId::new(state.service_id().clone())
        .map_err(|error| format!("receiver service id is invalid: {error}"))?;
    let (_, receiver_method) = state
        .current_service_receipt_binding()
        .await
        .map_err(|error| format!("receiver receipt method is unavailable: {error}"))?;
    let receipt_key = format!(
        "agent-event-admission-receipt:{}:{}:{}",
        event.event_id, admission.event_digest, receiver_service_id
    );
    if let Some(record) = state
        .persistence()
        .idempotency_record(receiver_service_id.as_str(), &receipt_key)
        .await
        .map_err(|error| format!("receipt lookup failed: {error}"))?
    {
        serde_json::from_value::<AgentEventAdmissionReceipt>(record.response_body)
            .map_err(|error| format!("stored receipt is invalid: {error}"))?;
        return Ok(Some(PreparedAgentEventAdmissionReceipt {
            idempotency: None,
        }));
    }
    let mut receipt = AgentEventAdmissionReceipt {
        schema: arkret_wire::NonEmptyString::new(
            arkret_wire::SchemaId::AGENT_SIGNER_ADMISSION_RECEIPT_V1.to_owned(),
        )
        .map_err(|error| error.to_string())?,
        event_id: event.event_id.clone(),
        event_digest: admission.event_digest.clone(),
        realm_id: event.realm_id.clone(),
        producer_accepted_at: admission.accepted_at,
        accepted_at,
        agent_id: event
            .executed_by
            .as_ref()
            .unwrap_or(&event.actor_id)
            .clone(),
        verification_method: admission.producer_verification_method.clone(),
        producer_signer_resolution_evidence_ref: producer_evidence_ref,
        producer_signer_resolution_evidence_digest: producer_evidence_digest,
        receiver_service_id: receiver_service_id.clone(),
        proof: AgentDetachedJws {
            kind: arkret_wire::NonEmptyString::new("detached_jws".to_owned())
                .map_err(|error| error.to_string())?,
            jws: arkret_wire::NonEmptyString::new("pending".to_owned())
                .map_err(|error| error.to_string())?,
        },
    };
    arkret_signatures::agent_evidence::sign_agent_event_admission_receipt(
        &mut receipt,
        &receiver_method,
        state.notary_signing_key().as_ref(),
    )
    .map_err(|reason| reason.as_str().to_owned())?;
    let body = serde_json::to_value(&receipt)
        .map_err(|error| format!("receipt encoding failed: {error}"))?;
    Ok(Some(PreparedAgentEventAdmissionReceipt {
        idempotency: Some(soland_services::events::IdempotentResponse {
            principal_id: receiver_service_id.as_str().to_owned(),
            key: receipt_key,
            service_id: state.service_id().clone(),
            request_hash: admission.event_digest.as_str().to_owned(),
            status: 200,
            body,
            created_at: accepted_at,
            expires_at: accepted_at + chrono::Duration::days(36500),
        }),
    }))
}

async fn load_agent_event_admission_receipt(
    state: &AppState,
    event: &arkret_wire::Event,
) -> Result<Option<arkret_models_identity::agent_signer_evidence::AgentEventAdmissionReceipt>, String>
{
    if event.actor_kind != Some(arkret_wire::EnvelopeActorKind::Agent) {
        return Ok(None);
    }
    let admission = event
        .proofs
        .iter()
        .find_map(|proof| match proof {
            arkret_wire::EventProof::PrincipalServerAdmission(value) => Some(value),
            arkret_wire::EventProof::Producer(_) => None,
        })
        .ok_or_else(|| "federated Event omitted its Principal Server admission proof".to_owned())?;
    let receiver_service_id = arkret_wire::DidCoreId::new(state.service_id().clone())
        .map_err(|error| format!("receiver service id is invalid: {error}"))?;
    let receipt_key = format!(
        "agent-event-admission-receipt:{}:{}:{}",
        event.event_id, admission.event_digest, receiver_service_id
    );
    let stored = state
        .persistence()
        .idempotency_record(receiver_service_id.as_str(), &receipt_key)
        .await
        .map_err(|error| format!("receipt replay lookup failed: {error}"))?
        .ok_or_else(|| "atomic receipt did not become visible".to_owned())?;
    let stored = serde_json::from_value(stored.response_body)
        .map_err(|error| format!("stored receipt is invalid: {error}"))?;
    Ok(Some(stored))
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
    let exact: [&arkret_wire::Event; 4] = events
        .try_into()
        .expect("typed founding federation carrier has exactly four Events");
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
    let event_principal_server_ids = submission
        .events
        .iter()
        .map(|item| item.event.principal_server_id.as_str())
        .collect::<Vec<_>>();
    if arkret_wire::DidCoreId::new(source_service_id.to_owned()).is_err()
        || !direct_founding_origin_ids_match(
            source_service_id,
            receipt.issuer_service_id.as_str(),
            &event_principal_server_ids,
        )
    {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "capability_denied",
            "authenticated source, founding receipt issuer and every Event principal server must match",
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
    if !direct_bootstrap_source_is_contact_authority(
        state,
        receipt.issuer_service_id.as_str(),
        &envelopes,
    )
    .await
    {
        render_error(
            res,
            StatusCode::CONFLICT,
            "dependency_missing",
            "the Direct Conversation Contact round mirror is not available",
        );
        return;
    }
    let founding_events = submission
        .events
        .iter()
        .map(|item| &item.event)
        .collect::<Vec<_>>();
    let founding_digest_suites =
        match trusted_federated_event_digest_suites(state, &founding_events) {
            Ok(value) => value,
            Err(error) => {
                render_error(res, StatusCode::BAD_REQUEST, "schema_violation", &error);
                return;
            }
        };
    let mut admitted_producers = BTreeMap::new();
    for (item, digest_suite) in submission
        .events
        .iter()
        .zip(founding_digest_suites.iter().copied())
    {
        match verify_federated_event_admission(state, &item.event, digest_suite).await {
            Ok(producer) => {
                admitted_producers.insert(item.event.event_id.to_string(), producer);
            }
            Err(error) => {
                render_error(
                    res,
                    StatusCode::BAD_REQUEST,
                    "invalid_proof",
                    &format!("founding Event admission proof is invalid: {error}"),
                );
                return;
            }
        }
    }
    let created_at = now();
    let session = SessionRecord {
        token_hash: format!("federation:direct-conversation:{request_hash}"),
        actor: receipt.founder_id.to_string(),
        device_id: submission.events[0]
            .event
            .payload
            .get("device_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            // Deviceless relayed founding unit, not a device named after the lane.
            .unwrap_or_default(),
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
            let (verification_method, signing_key) = admitted_producers
                .get(item.event.event_id.as_str())
                .expect("every founding Event was admission-verified");
            InternalEventAdmission::peer_federated_event(
                plan.realm_id.to_string(),
                receipt.founder_id.to_string(),
                session.device_id.clone(),
                item.event.event_id.to_string(),
                verification_method.clone(),
                signing_key.clone(),
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

fn direct_founding_origin_ids_match(
    source_service_id: &str,
    receipt_issuer_service_id: &str,
    event_principal_server_ids: &[&str],
) -> bool {
    !source_service_id.is_empty()
        && source_service_id == receipt_issuer_service_id
        && event_principal_server_ids.len() == 3
        && event_principal_server_ids
            .iter()
            .all(|principal_server_id| *principal_server_id == source_service_id)
}

#[cfg(test)]
mod direct_founding_origin_tests {
    use super::direct_founding_origin_ids_match;

    #[test]
    fn direct_founding_source_receipt_and_every_event_share_one_origin() {
        let source = "ak:did_core:web:remote.example";
        assert!(direct_founding_origin_ids_match(
            source,
            source,
            &[source, source, source]
        ));
        assert!(!direct_founding_origin_ids_match(
            source,
            source,
            &[source, "ak:did_core:web:other.example", source]
        ));
        assert!(!direct_founding_origin_ids_match(
            source,
            "ak:did_core:web:other.example",
            &[source, source, source]
        ));
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
pub(in crate::routing) use value::{
    DevicePairingAdmission, submit_account_data_event_value, submit_event_value,
    submit_initial_event_submission, submit_initial_event_submission_with_contact_projection,
    submit_initial_event_submission_with_device_pairing, submit_mimi_event_value,
    submit_mimi_moderation_report_event_value,
};
pub(in crate::routing::events::event_log) use value::{
    replay_ackless_self_principal_ingress, submit_event_value_with_idempotency,
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
        let agent_id = arkret_identifiers::DidFullId::new(
            "did:webvh:z6mkfixtureagent:agent.example".to_owned(),
        )
        .unwrap();
        let agent_actor_id = arkret_wire::project_full_id_to_core_id(&agent_id).unwrap();
        let genesis =
            arkret_models_collaboration::events_payloads::RealmGenesis::managed_agent_control(
                arkret_wire::GenesisSalt::new(
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                )
                .unwrap(),
                arkret_models_identity::ResolutionCommitment {
                    full_id: agent_id.clone(),
                    method_history_head: format!("sha256:{}", "8".repeat(64)),
                    version_id: "1-Qmfixture".to_owned(),
                },
                arkret_identifiers::TrustDomainId::new(
                    "ak:trust_domain:managed-agent-pcr".to_owned(),
                )
                .unwrap(),
                vec!["ak.profile.principal_control_realm.v1".to_owned()],
                arkret_wire::CORE_REDUCER_PROFILE,
                arkret_canonical::DigestSuite::Sha256,
                arkret_wire::SecurityClass::HighAssurance,
                arkret_wire::EncryptionProfile::MlsRfc9420,
                crate::test_single_signer_notary("did:webvh:z6mkfixtureagent:agent.example", 43),
                arkret_policy::current_capability_action_registry_digest().unwrap(),
            )
            .unwrap();
        let payload =
            arkret_models_collaboration::events_payloads::RealmCreatePayload::new(genesis)
                .to_value()
                .unwrap();
        let mut event = crate::test_event::raw_event(
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
        internal_session("did:web:mimi.example", "")
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
            "ak:did_core:web:local.example",
            now,
            std::slice::from_ref(&frontier),
            vec![member_view(
                "ak:did_core:web:alice.example",
                "ak:did_core:web:local.example",
                &frontier,
                now,
            )],
        );

        assert!(matches!(result, FederationServiceBindingCheck::Current));
    }

    #[test]
    fn federation_service_binding_check_rejects_empty_frontier_as_schema_violation() {
        let now = Utc::now();
        let result = federation_service_binding_check_from_members(
            "ak:did_core:web:local.example",
            now,
            &[],
            vec![member_view(
                "ak:did_core:web:alice.example",
                "ak:did_core:web:local.example",
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
            "ak:did_core:web:old.example",
            now,
            std::slice::from_ref(&old_frontier),
            vec![member_view(
                "ak:did_core:web:alice.example",
                "ak:did_core:web:new.example",
                &new_frontier,
                now - Duration::seconds(60),
            )],
        );

        match result {
            FederationServiceBindingCheck::Stale(evidence) => {
                assert_eq!(
                    evidence.new_recipient_service_id.as_str(),
                    "ak:did_core:web:new.example"
                );
                assert_eq!(evidence.actor_id.as_str(), "ak:did_core:web:alice.example");
                assert_eq!(evidence.handover_frontier, vec![new_frontier]);
            }
            other => panic!("expected stale handover evidence, got {other:?}"),
        }
    }

    #[test]
    fn federation_service_binding_check_emits_handed_over_after_grace_expires() {
        let now = Utc::now();
        let result = federation_service_binding_check_from_members(
            "ak:did_core:web:old.example",
            now,
            &[event_id(1)],
            vec![member_view(
                "ak:did_core:web:alice.example",
                "ak:did_core:web:new.example",
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
            "ak:did_core:web:old.example",
            now,
            &[event_id(1)],
            vec![
                member_view(
                    "ak:did_core:web:alice.example",
                    "ak:did_core:web:new.example",
                    &event_id(2),
                    now,
                ),
                member_view(
                    "ak:did_core:web:bob.example",
                    "ak:did_core:web:other.example",
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
