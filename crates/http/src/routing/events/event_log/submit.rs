use std::hash::Hasher;
use std::sync::{Arc, OnceLock};

use arkret_event_draft::EventPayloadExt as _;

use super::*;

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
const IDENTITY_CREATION_CONTROL_PROOF_MAX_FUTURE_SKEW_SECONDS: i64 = 30;

static ACTOR_SUBMIT_LOCKS: OnceLock<Vec<Arc<tokio::sync::Mutex<()>>>> = OnceLock::new();
static ACCOUNT_DATA_SUBMIT_LOCKS: OnceLock<Vec<Arc<tokio::sync::Mutex<()>>>> = OnceLock::new();
static INVITE_LIFECYCLE_LOCKS: OnceLock<Vec<Arc<tokio::sync::Mutex<()>>>> = OnceLock::new();
static SERVICE_EVENT_AUTHORING_LOCK: OnceLock<Arc<tokio::sync::Mutex<()>>> = OnceLock::new();

mod ghost_provision;
pub(in crate::routing) use ghost_provision::{applet_committed_ref, submit_applet_authoring_unit};
mod sidecar_ensure;
pub(crate) use sidecar_ensure::submit_sidecar_ensure_batch;
mod agent_membership_cascade;
pub(in crate::routing) use agent_membership_cascade::submit_agent_membership_cascade;

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

#[derive(Debug)]
pub(in crate::routing) struct ValidatedEventEnvelope {
    pub(in crate::routing) event_id: EventId,
    pub(in crate::routing) actor: arkret_wire::ActorId,
    pub(in crate::routing) actor_id: DidCoreId,
    /// Submitting device, absent for a deviceless service session.
    pub(in crate::routing) device_id: Option<DeviceId>,
    pub(in crate::routing) realm_id: RealmId,
    pub(in crate::routing) kind: String,
    pub(in crate::routing) schema_id: String,
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
pub(in crate::routing) enum SubmitOneError {
    Rejected {
        error: Box<AppError>,
        details: Option<Value>,
    },
    Quarantined {
        event_id: String,
        reason_code: String,
        message: String,
    },
}

#[derive(Debug)]
pub(in crate::routing) struct SubmittedEventOutcome {
    pub event_id: String,
    pub duplicate: bool,
}

#[derive(Debug)]
pub(in crate::routing) struct EventCommitIdempotency {
    pub authenticated_actor: arkret_wire::ActorId,
    pub operation_id: String,
    pub key: String,
    pub request_hash: String,
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
    actor_id: arkret_wire::ActorId,
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
    AppletFormal {
        event_id: String,
        applet_id: arkret_wire::AppletId,
        staged_producer_authority: Option<(arkret_wire::DidUrl, arkret_wire::DidKey)>,
    },
    SidecarEnsure {
        event_id: String,
    },
    AgentMembershipCascade {
        event_id: String,
        initiator_id: arkret_wire::ActorId,
    },
    PeerFederatedEvent {
        event_id: String,
        producer_verification_method: arkret_wire::DidUrl,
        producer_signing_key: arkret_wire::DidKey,
    },
    ProofAuthenticatedEvent {
        event_id: String,
        producer_verification_method: arkret_wire::DidUrl,
        producer_signing_key: arkret_wire::DidKey,
    },
    PeerAgentMembershipCascade {
        event_id: String,
        initiator_id: arkret_wire::ActorId,
        producer_verification_method: arkret_wire::DidUrl,
        producer_signing_key: arkret_wire::DidKey,
    },
}

impl InternalEventAdmission {
    pub(in crate::routing::events::event_log) fn is_peer_replication(&self) -> bool {
        matches!(
            self.binding,
            InternalEventBinding::PeerFederatedEvent { .. }
                | InternalEventBinding::PeerAgentMembershipCascade { .. }
        )
    }
    pub(in crate::routing::events::event_log) fn is_applet_formal(&self) -> bool {
        matches!(self.binding, InternalEventBinding::AppletFormal { .. })
    }
    pub(in crate::routing) fn mimi_provider(
        realm_id: impl Into<String>,
        actor_id: arkret_wire::ActorId,
        binding_ref: impl Into<String>,
    ) -> Self {
        Self {
            realm_id: realm_id.into(),
            session_actor_id: actor_id.signing_principal_id().to_string(),
            actor_id,
            kind: arkret_wire::EventKind::MessageCreate.as_str().to_owned(),
            device_id: String::new(),
            binding: InternalEventBinding::MimiProvider {
                binding_ref: binding_ref.into(),
            },
        }
    }

    pub(in crate::routing) fn applet_formal(
        realm_id: impl Into<String>,
        actor_id: arkret_wire::ActorId,
        kind: impl Into<String>,
        event_id: impl Into<String>,
        applet_id: arkret_wire::AppletId,
        staged_producer_authority: Option<(arkret_wire::DidUrl, arkret_wire::DidKey)>,
    ) -> Self {
        Self {
            realm_id: realm_id.into(),
            session_actor_id: actor_id.signing_principal_id().to_string(),
            actor_id,
            kind: kind.into(),
            device_id: String::new(),
            binding: InternalEventBinding::AppletFormal {
                event_id: event_id.into(),
                applet_id,
                staged_producer_authority,
            },
        }
    }

    pub(in crate::routing) fn sidecar_ensure(
        realm_id: impl Into<String>,
        actor_id: arkret_wire::ActorId,
        device_id: impl Into<String>,
        kind: impl Into<String>,
        event_id: impl Into<String>,
    ) -> Self {
        Self {
            realm_id: realm_id.into(),
            session_actor_id: actor_id.signing_principal_id().to_string(),
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
        actor_id: arkret_wire::ActorId,
        initiator_id: arkret_wire::ActorId,
        device_id: impl Into<String>,
        event_id: impl Into<String>,
    ) -> Self {
        Self {
            realm_id: realm_id.into(),
            actor_id,
            session_actor_id: initiator_id.signing_principal_id().to_string(),
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
        actor_id: arkret_wire::ActorId,
        device_id: impl Into<String>,
        event_id: impl Into<String>,
        producer_verification_method: arkret_wire::DidUrl,
        producer_signing_key: arkret_wire::DidKey,
    ) -> Self {
        Self {
            realm_id: realm_id.into(),
            session_actor_id: actor_id.signing_principal_id().to_string(),
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

    pub(in crate::routing) fn proof_authenticated_event(
        event: &arkret_wire::Event,
        device_id: impl Into<String>,
        producer_signing_key: arkret_wire::DidKey,
    ) -> Self {
        let signer = event.executed_by.as_ref().unwrap_or(&event.actor_id);
        Self {
            realm_id: event.realm_id.to_string(),
            actor_id: event.actor_id.clone(),
            session_actor_id: signer.signing_principal_id().to_string(),
            kind: event.kind.as_str().to_owned(),
            device_id: device_id.into(),
            binding: InternalEventBinding::ProofAuthenticatedEvent {
                event_id: event.event_id.to_string(),
                producer_verification_method: event
                    .producer_proof
                    .as_ref()
                    .expect("validated producer proof")
                    .verification_method
                    .clone(),
                producer_signing_key,
            },
        }
    }

    pub(in crate::routing) fn peer_agent_membership_cascade(
        realm_id: impl Into<String>,
        actor_id: arkret_wire::ActorId,
        initiator_id: arkret_wire::ActorId,
        device_id: impl Into<String>,
        event_id: impl Into<String>,
        producer_verification_method: arkret_wire::DidUrl,
        producer_signing_key: arkret_wire::DidKey,
    ) -> Self {
        Self {
            realm_id: realm_id.into(),
            session_actor_id: initiator_id.signing_principal_id().to_string(),
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
            && match &session.endpoint {
                soland_services::identity::SessionEndpointState::HumanDevice { device_id } => {
                    device_id == &self.device_id
                }
                soland_services::identity::SessionEndpointState::ServiceSynthetic => {
                    self.device_id.is_empty()
                }
                soland_services::identity::SessionEndpointState::AgentRuntime { .. } => false,
            }
            && object
                .get("actor_id")
                .cloned()
                .and_then(|value| serde_json::from_value::<arkret_wire::ActorId>(value).ok())
                .as_ref()
                == Some(&self.actor_id)
            && self.matches_realm_coordinate(object)
            && (self.kind.is_empty()
                || object.get("kind").and_then(Value::as_str) == Some(self.kind.as_str()))
            && match &self.binding {
                InternalEventBinding::MimiProvider { binding_ref } => {
                    object
                        .get("payload")
                        .and_then(|payload| payload.get("mimi_provenance"))
                        .and_then(|provenance| provenance.get("room_binding_ref"))
                        .and_then(Value::as_str)
                        == Some(binding_ref.as_str())
                }
                InternalEventBinding::AppletFormal {
                    event_id,
                    applet_id,
                    ..
                } => {
                    object.get("event_id").and_then(Value::as_str) == Some(event_id.as_str())
                        && object.get("applet_id").and_then(Value::as_str)
                            == Some(applet_id.as_str())
                }
                InternalEventBinding::SidecarEnsure { event_id } => {
                    object.get("event_id").and_then(Value::as_str) == Some(event_id.as_str())
                }
                InternalEventBinding::AgentMembershipCascade {
                    event_id,
                    initiator_id,
                } => {
                    object.get("event_id").and_then(Value::as_str) == Some(event_id.as_str())
                        && object
                            .get("executed_by")
                            .cloned()
                            .map(serde_json::from_value::<arkret_wire::ActorId>)
                            .transpose()
                            .ok()
                            .map(|actor| actor.unwrap_or_else(|| self.actor_id.clone()))
                            .as_ref()
                            == Some(initiator_id)
                }
                InternalEventBinding::PeerFederatedEvent { event_id, .. } => {
                    object.get("event_id").and_then(Value::as_str) == Some(event_id.as_str())
                }
                InternalEventBinding::ProofAuthenticatedEvent { event_id, .. } => {
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
                            .cloned()
                            .map(serde_json::from_value::<arkret_wire::ActorId>)
                            .transpose()
                            .ok()
                            .map(|actor| actor.unwrap_or_else(|| self.actor_id.clone()))
                            .as_ref()
                            == Some(initiator_id)
                }
            }
    }

    fn matches_realm_coordinate(&self, object: &serde_json::Map<String, Value>) -> bool {
        if let Some(realm_id) = object.get("realm_id").and_then(Value::as_str) {
            return realm_id == self.realm_id;
        }
        if object.get("kind").and_then(Value::as_str)
            != Some(arkret_wire::EventKind::RealmCreate.as_str())
        {
            return false;
        }
        object
            .get("event_id")
            .and_then(Value::as_str)
            .and_then(|event_id| arkret_wire::EventId::new(event_id.to_owned()).ok())
            .is_some_and(|event_id| {
                arkret_wire::RealmId::from_event_id(&event_id).as_str() == self.realm_id
            })
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
            InternalEventBinding::ProofAuthenticatedEvent {
                producer_verification_method,
                producer_signing_key,
                ..
            } if producer_verification_method.as_str() == verification_method => {
                Some(producer_signing_key)
            }
            _ => None,
        }
    }

    pub(in crate::routing::events::event_log) fn applet_formal_producer_signing_key(
        &self,
        session: &SessionRecord,
        object: &serde_json::Map<String, Value>,
        verification_method: &str,
    ) -> Option<&arkret_wire::DidKey> {
        if !self.matches(session, object) {
            return None;
        }
        match &self.binding {
            InternalEventBinding::AppletFormal {
                staged_producer_authority:
                    Some((producer_verification_method, producer_signing_key)),
                ..
            } if producer_verification_method.as_str() == verification_method => {
                Some(producer_signing_key)
            }
            _ => None,
        }
    }

    pub(in crate::routing::events::event_log) fn authorizes_mimi_facade_write(
        &self,
        session: &SessionRecord,
        object: &serde_json::Map<String, Value>,
    ) -> bool {
        matches!(self.binding, InternalEventBinding::MimiProvider { .. })
            && self.matches(session, object)
    }

    /// Return whether this is one of the closed internal adapters whose
    /// producer is the local service principal itself.
    ///
    /// This is deliberately an exact binding allowlist, not a session-shape
    /// shortcut: service-authored Events use the service DID's notary method
    /// as their producer proof authority, while user/device, Applet, Agent and
    /// federated Events must continue through their own proof branches.
    pub(in crate::routing::events::event_log) fn is_local_service_producer(
        &self,
        session: &SessionRecord,
        object: &serde_json::Map<String, Value>,
    ) -> bool {
        matches!(self.binding, InternalEventBinding::MimiProvider { .. })
            && self.matches(session, object)
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
                    | InternalEventBinding::ProofAuthenticatedEvent { .. }
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

impl SubmitOneError {
    /// Carry an admission rejection that was already shaped as an `AppError`
    /// without flattening its wire code into prose.
    pub(in crate::routing) fn from_app_error(error: AppError) -> Self {
        Self::Rejected {
            error: Box::new(error),
            details: None,
        }
    }

    pub(in crate::routing) fn new(
        status: StatusCode,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        let code = code.into();
        let message = message.into();
        let error = if let Some(code) = ErrorCode::from_wire(&code) {
            AppError::from_rejection(code, message)
        } else {
            let mapped = match status {
                StatusCode::PRECONDITION_FAILED => ErrorCode::FailedPrecondition,
                StatusCode::CONFLICT => ErrorCode::Conflict,
                StatusCode::FORBIDDEN => ErrorCode::CapabilityDenied,
                StatusCode::UNAUTHORIZED => ErrorCode::Unauthenticated,
                StatusCode::BAD_REQUEST => ErrorCode::ParamInvalid,
                StatusCode::UNPROCESSABLE_ENTITY => ErrorCode::SchemaViolation,
                _ => ErrorCode::InternalError,
            };
            AppError::from_rejection(mapped, message).with_internal_reason(code)
        };
        Self::Rejected {
            error: Box::new(error),
            details: None,
        }
    }

    pub(in crate::routing) fn with_details(mut self, details: impl serde::Serialize) -> Self {
        if let Self::Rejected {
            details: wire_details,
            ..
        } = &mut self
        {
            *wire_details = serde_json::to_value(details).ok();
        }
        self
    }

    /// A registered operation-semantic rejection is always a schema violation
    /// at the top level, while its stable machine discriminator belongs in
    /// `error.details.reason_code`. Keeping this mapping here prevents each
    /// admission lane from silently flattening the reason back into prose.
    /// Discriminators that are not registered reason codes are routed to the
    /// unstable `reason_detail` key instead.
    pub(in crate::routing) fn semantic_schema_violation(reason_code: &'static str) -> Self {
        let detail_key = if arkret_wire::ReasonCode::is_registered(reason_code) {
            "reason_code"
        } else {
            "reason_detail"
        };
        Self::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "schema_violation",
            reason_code,
        )
        .with_details(serde_json::json!({
            detail_key: reason_code,
        }))
    }

    pub(in crate::routing) fn quarantine(
        event_id: impl Into<String>,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::Quarantined {
            event_id: event_id.into(),
            reason_code: code.into(),
            message: message.into(),
        }
    }

    pub(in crate::routing) fn rejection(&self) -> Option<&AppError> {
        match self {
            Self::Rejected { error, .. } => Some(error),
            Self::Quarantined { .. } => None,
        }
    }

    pub(in crate::routing) fn direct_conversation_admission_reason(&self) -> Option<&str> {
        let Self::Rejected { error, details } = self else {
            return None;
        };
        details
            .as_ref()
            .and_then(Value::as_object)
            .and_then(|details| details.get("reason_code"))
            .and_then(Value::as_str)
            .or(error.reason_code.as_deref())
            .filter(|reason| is_direct_conversation_admission_reason(reason))
    }

    pub(in crate::routing) fn details(&self) -> Option<&Value> {
        match self {
            Self::Rejected { details, .. } => details.as_ref(),
            Self::Quarantined { .. } => None,
        }
    }

    pub(in crate::routing) fn quarantine_event_id(&self) -> Option<String> {
        match self {
            Self::Quarantined { event_id, .. } => Some(event_id.clone()),
            Self::Rejected { .. } => None,
        }
    }

    pub(in crate::routing) fn status(&self) -> StatusCode {
        self.rejection()
            .map_or(StatusCode::OK, AppError::http_status)
    }

    pub(in crate::routing) fn code(&self) -> String {
        match self {
            Self::Rejected { error, .. } => error
                .reason_code
                .as_deref()
                .unwrap_or_else(|| error.wire_code())
                .to_owned(),
            Self::Quarantined { reason_code, .. } => reason_code.clone(),
        }
    }

    pub(in crate::routing) fn message(&self) -> String {
        match self {
            Self::Rejected { error, .. } => error.message.to_string(),
            Self::Quarantined { message, .. } => message.clone(),
        }
    }
}

pub(super) fn is_direct_conversation_admission_reason(reason: &str) -> bool {
    matches!(
        reason,
        arkret_wire::ReasonCode::DIRECT_CONVERSATION_BINDING_INVALID
            | arkret_wire::ReasonCode::DIRECT_CONVERSATION_TERMINAL_FORBIDDEN
            | arkret_wire::ReasonCode::DIRECT_CONVERSATION_MEMBER_COUNT_INVALID
            | arkret_wire::ReasonCode::DIRECT_CONVERSATION_THIRD_PARTY_MEMBER_FORBIDDEN
            | arkret_wire::ReasonCode::DIRECT_CONVERSATION_INVITE_FORBIDDEN
            | arkret_wire::ReasonCode::DIRECT_CONVERSATION_ROOT_MASK_VIOLATION
            | arkret_wire::ReasonCode::DIRECT_CONVERSATION_PARTICIPANT_AUTHORITY_DENIED
    )
}

pub(super) fn validate_membership_compensation_semantics(
    event: &arkret_wire::Event,
    evidence: Option<&arkret_wire::MembershipCompensationSubmissionEvidence>,
) -> Result<(), SubmitOneError> {
    let Some(evidence) = evidence else {
        return Ok(());
    };
    evidence.validate_for_event(event).map_err(|error| {
        SubmitOneError::new(
            StatusCode::CONFLICT,
            "membership_compensation_conflict",
            format!("membership compensation evidence is invalid: {error}"),
        )
    })
}

/// Map a rejected Event submission onto the HTTP error family without losing the
/// wire discriminator.
///
/// A caller-signed Event that ordinary admission rejects has a real reason, and
/// `context` names the surface that submitted it. Reducer rejection reasons (for
/// example `circle_realm_mismatch` or `grant_exceeds_issuer_authority`) are
/// stable *reason* codes, not top-level error codes: one that is not a registered
/// error code keeps its semantic HTTP class and travels in `reason_code` when it
/// is a registered reason code (internal discriminators fall back to the unstable
/// `reason_detail`), rather than being flattened into a misleading 500
/// internal_error.
pub(in crate::routing) fn submit_one_error_to_app_error(
    context: &str,
    status: StatusCode,
    code: impl Into<String>,
    detail: &str,
) -> AppError {
    let code = code.into();
    let message = format!("{context}: {detail}");
    // The Circle subset invariant is a registered sub-reason of
    // `failed_precondition`, not a top-level error code. Preserve the 422
    // admission class and carry the exact reducer discriminator separately.
    if code == arkret_wire::ReasonCode::CIRCLE_MEMBER_MUST_BE_REALM_MEMBER {
        return crate::app_error!(FailedPrecondition, message).with_reason_code(code);
    }
    // relation.md §4 and the error registry bind this reducer sub-reason to
    // top-level failed_precondition (HTTP 409). Do not preserve the internal
    // projection-preflight 412 carrier: 412 is reserved for HTTP/CBS
    // preconditions and is not the registered wire status for this verdict.
    if code == arkret_wire::ReasonCode::CROSS_REALM_STRUCTURAL_RELATION {
        return crate::app_error!(FailedPrecondition, message).with_reason_code(code);
    }
    // The bounded inline snapshot capacity is a registered failed_precondition
    // reason of every Realm-stream append, not a top-level code.
    if code == arkret_wire::ReasonCode::SNAPSHOT_CAPACITY_EXCEEDED {
        return crate::app_error!(FailedPrecondition, message).with_reason_code(code);
    }
    // AK-NC grant authority clause: a first-issued grant outside its issuer's
    // authority is `failed_precondition` with this registered reason.
    if code == arkret_wire::ReasonCode::GRANT_EXCEEDS_ISSUER_AUTHORITY {
        return crate::app_error!(FailedPrecondition, message).with_reason_code(code);
    }
    if let Some(mapped) = ErrorCode::from_wire(&code) {
        return AppError::from_rejection(mapped, message);
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
    AppError::from_rejection(mapped, message).with_internal_reason(code)
}

fn cbs_bottom_reject(reason: &'static str) -> (&'static str, &'static str) {
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
            let registered = arkret_wire::ReasonCode::is_registered(reason_code);
            if let Self::Rejected { error, .. } = &mut rendered {
                error.attach_internal_reason(reason_code);
            }
            let detail_key = if registered {
                "reason_code"
            } else {
                "reason_detail"
            };
            rendered = rendered.with_details(serde_json::json!({
                detail_key: reason_code,
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

/// Accept the one registered pre-grant PCR genesis carrier after the peer
/// transport has authenticated the Account Authority service.
pub(in crate::routing) async fn submit_peer_pcr_genesis(
    state: &AppState,
    request: &arkret_models_collaboration::principal_operations::PcrGenesisAdmissionInput,
    exact_request_body: Vec<u8>,
) -> Result<
    arkret_models_collaboration::principal_operations::PcrGenesisAdmissionResult,
    SubmitOneError,
> {
    request.validate().map_err(|error| {
        SubmitOneError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
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
                StatusCode::UNPROCESSABLE_ENTITY,
                "schema_violation",
                format!("invalid PCR genesis create payload: {error}"),
            )
        })?;
    let descriptor = create_payload
        .object
        .founding_device_descriptor
        .ok_or_else(|| {
            SubmitOneError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "schema_violation",
                "PCR genesis omits its founding device descriptor",
            )
        })?;
    let accepted_device_id = descriptor.device_id.clone();
    // Exact replay is resolved before the short-lived proof's freshness gate.
    // The PG ledger compares the original HTTP bytes and idempotency key,
    // including after proof expiry; matching Event ids alone prove no replay.
    if let Some(outcome) = state
        .authority_commits()
        .pcr_genesis_replay(request, &exact_request_body)
        .await
        .map_err(|error| {
            let (status, code) = if error.is_conflict_kind() {
                (StatusCode::CONFLICT, "duplicate_conflict")
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
            };
            SubmitOneError::new(
                status,
                code,
                format!("PCR genesis replay lookup failed: {error}"),
            )
        })?
    {
        outcome.validate_against(request).map_err(|error| {
            SubmitOneError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("stored PCR genesis replay result is invalid: {error}"),
            )
        })?;
        return Ok(outcome);
    }
    validate_identity_creation_control_proof(state, request).await?;
    let authority = soland_storage::CurrentRealmAuthority {
        realm_id: request.pcr_realm_id.clone(),
        generation: 0,
        service_id: request.account_authority_id.clone(),
        authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
            request.genesis_unit.create().event_id.clone(),
        ),
        last_handoff_ref: None,
    };
    let verification_method = arkret_wire::DidUrl::new(
        crate::routing::federation::federation_service_signature_key_id(
            state.service_did().as_str(),
        ),
    )
    .map_err(|error| {
        SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            format!("PCR authority signing method is invalid: {error}"),
        )
    })?;
    let queued_at = Utc::now();
    let unit = state
        .authority_commits()
        .prepare_pcr_genesis_unit(
            request.clone(),
            exact_request_body,
            &authority,
            verification_method,
            state.notary_signing_key().as_ref(),
            queued_at,
        )
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "schema_violation",
                format!("PCR genesis authority preparation failed: {error}"),
            )
        })?;
    let result = state
        .authority_commits()
        .admit_pcr_genesis_unit(&unit, queued_at)
        .await
        .map_err(|error| {
            let (status, code) = if error.is_conflict_kind() {
                (StatusCode::CONFLICT, "duplicate_conflict")
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
            };
            SubmitOneError::new(status, code, format!("PCR genesis commit failed: {error}"))
        })?;
    let outcome = match result {
        soland_storage::PcrGenesisCommitOutcome::Committed(outcome)
        | soland_storage::PcrGenesisCommitOutcome::Duplicate(outcome) => outcome,
    };
    if outcome.accepted_device_id != accepted_device_id {
        return Err(SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "PCR genesis result changed the founding device binding",
        ));
    }
    outcome.validate_against(request).map_err(|error| {
        SubmitOneError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            format!("committed PCR genesis outcome is invalid: {error}"),
        )
    })?;
    Ok(outcome)
}

async fn validate_identity_creation_control_proof(
    state: &AppState,
    request: &arkret_models_collaboration::principal_operations::PcrGenesisAdmissionInput,
) -> Result<(), SubmitOneError> {
    let proof = &request.identity_creation_control_proof;
    let now = Utc::now();
    // The complete historical registration evidence carries no freshness gate
    // against this receiver's clock: its `accepted_at` is the relaying
    // Authority's registry acceptance instant, not a claim about now.
    if !identity_creation_control_proof_window_valid(proof.issued_at, proof.expires_at, now)
        || proof.audience_id.as_str() != state.service_id().as_str()
    {
        return Err(SubmitOneError::new(
            StatusCode::UNAUTHORIZED,
            "signature_invalid",
            "identity creation control proof is expired or has the wrong audience",
        ));
    }
    let validated_anchor = arkret_identity::validate_principal_registration_anchor(
        &request.principal_registration_anchor,
    )
    .map_err(|error| {
        SubmitOneError::new(
            StatusCode::UNAUTHORIZED,
            "signature_invalid",
            format!("principal registration anchor is invalid: {error}"),
        )
    })?;
    arkret_signatures::webvh::verify_identity_creation_control_proof(&validated_anchor, proof)
        .map_err(|error| {
            SubmitOneError::new(
                StatusCode::UNAUTHORIZED,
                "signature_invalid",
                format!("identity creation proof is invalid: {error}"),
            )
        })?;
    let registration_did_operation = match &request.principal_registration_anchor {
        arkret_models_identity::PrincipalRegistrationAnchor::WebvhRegistration {
            registration_did_operation,
            ..
        } => registration_did_operation.as_ref(),
    };
    arkret_signatures::webvh::verify_registration_did_evidence_draft(
        registration_did_operation,
        &request.registration_did_evidence.draft(),
    )
    .map_err(|error| {
        SubmitOneError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "historical_did_evidence_invalid",
            format!("frozen registration DID evidence is invalid: {error}"),
        )
    })?;
    Ok(())
}

fn identity_creation_control_proof_window_valid(
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> bool {
    issued_at <= now + Duration::seconds(IDENTITY_CREATION_CONTROL_PROOF_MAX_FUTURE_SKEW_SECONDS)
        && expires_at > now
        && expires_at - issued_at <= Duration::minutes(5)
}

pub(super) fn event_actor_from_value(value: &Value) -> Option<arkret_wire::ActorId> {
    serde_json::from_value(value.get("actor_id")?.clone()).ok()
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

pub(super) mod post_commit;
mod value;

use post_commit::*;
pub(super) use value::validate_membership_compensation_live_state;
use value::*;
pub(in crate::routing) use value::{
    submit_applet_revoke_event_submission, submit_event_value, submit_initial_event_submission,
};
// `submit_one_error_to_app_error` is defined in this module, so it needs no
// re-export here; `event_log.rs` names it directly.

#[cfg(test)]
#[path = "submit_tests.rs"]
mod tests;
