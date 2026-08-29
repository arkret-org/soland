use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::{
    AccountDataRecord, CanonicalEventRecord, ConsentCellRecord, ContactRecord,
    ContactVerifiedMirrorRecord, DevicePairingAuthorizationCommit, DeviceRevocationGateSelector,
    DeviceRevocationTransition, FederationOutboxRecord, IdempotencyRecord, PersistenceError,
    PersistenceResult, ProjectionEventRecord,
};

/// One Contact projection mutation committed with its canonical Event and
/// federation intent. `expected_updated_at=None` is an insert-only slot;
/// `Some` is a whole-row CAS against the revision read by admission.
#[derive(Clone, Debug)]
pub struct ContactProjectionCommit {
    pub record: ContactRecord,
    pub expected_updated_at: Option<chrono::DateTime<chrono::Utc>>,
    pub conflict_code: String,
    pub verified_mirror: Option<ContactVerifiedMirrorRecord>,
    /// Optional holder-private policy mutation committed in the same unit as
    /// the Contact Event and lineage projection.
    pub invite_policy:
        Option<arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy>,
}

/// All durable writes produced by accepting one canonical event.
///
/// Adapters must make the complete request visible atomically. Returning an
/// error must leave the event log, projection log, idempotency table, and
/// federation outbox unchanged.
/// The holder-private consent effects of one accepted `ak.consent.grant` /
/// `ak.consent.revoke` Control Move.
///
/// `consent-model.md` section 4.1.2 requires the downstream invalidation to
/// land inside the same transaction boundary as the accepted revoke, and the
/// or_set cell mutation is what the Event *means*, so the cell row, the
/// invalidation and the canonical Event share one commit. Admission computes
/// all of it before acceptance; a rejected Move writes none of it.
#[derive(Clone, Debug)]
pub struct ConsentProjectionCommit {
    pub cell: ConsentCellRecord,
    /// Eager invite-quarantine invalidation for an accepted revoke
    /// (`consent-model.md` section 4.1.2), staged as a whole-value CAS against
    /// the revision admission read.
    pub invite_quarantine: Option<AccountDataCasCommit>,
}

/// One account-data cell replaced by revision CAS inside an Event commit.
#[derive(Clone, Debug)]
pub struct AccountDataCasCommit {
    pub record: AccountDataRecord,
    pub expected_revision: u64,
    pub conflict_code: String,
}

#[derive(Clone, Debug)]
pub struct EventCommitRequest {
    pub event: CanonicalEventRecord,
    /// Governance history edges whose source Control Event is this Event.
    /// These become visible in the same durable boundary as that source row.
    pub governance_dependencies: Vec<crate::GovernanceDependencyWrite>,
    /// Optional staged device-pairing CAS consumed in the same durable
    /// boundary as the canonical Event and its reducer projection.
    pub device_pairing_authorization: Option<DevicePairingAuthorizationCommit>,
    pub contact_projection: Option<ContactProjectionCommit>,
    /// Holder-private consent cell mutation plus its eager cache
    /// invalidation, committed with the Event that authorizes them.
    pub consent_projection: Option<ConsentProjectionCommit>,
    /// Durable ingress classification of an accepted Control Move
    /// (`event-auth-state-resolution.md` §7.2): `Some` iff the Event enters the
    /// pending-control log. The class and its payload are inseparable, so an
    /// Ack-required Move without its Ack is unrepresentable at this boundary.
    /// In the Ack-less class the Event proof itself is the proposal authority
    /// because this is an authority-authored Control Move in a self-principal
    /// PCR; such a Move deliberately carries no independent Control Proposal
    /// Ack, but still enters the canonical pending-control log for
    /// successor-Seal finality.
    pub control_proposal_ingress: Option<arkret_state::state::store::ControlProposalIngress>,
    /// Reducer-derived target for an accepted `ak.device.revoke`. The target
    /// and canonical Ack commit in the same transaction as the Event.
    pub device_revocation_transition: Option<DeviceRevocationTransition>,
    /// Exact author-device generation rechecked inside the Event transaction.
    pub device_revocation_gate: Option<DeviceRevocationGateSelector>,
    pub projections: Vec<ProjectionEventRecord>,
    pub idempotency: Option<IdempotencyRecord>,
    pub outbox: Vec<FederationOutboxRecord>,
}

/// Static persistence-side guard for the one Ack-less Control-Move class.
///
/// The HTTP admission layer additionally proves the PCR profile, current
/// `single_signer.actor_id == principal` authority and active accepted device generation.
/// Persistence cannot resolve those live projections, but it still refuses an
/// exemption whose immutable Event shape is not a self-principal PCR device
/// Move. This keeps the explicit commit flag from becoming a generic Ack
/// bypass.
#[must_use]
pub fn has_self_principal_pcr_device_authorized_shape(
    event: &arkret_wire::Event,
    digest_suite: arkret_canonical::DigestSuite,
) -> bool {
    if !event.kind.is_reducer_input()
        || event.seal_ref.is_some()
        || event.auth_context.is_some()
        || event.executed_by.is_some()
        || event
            .seal_basis
            .as_ref()
            .is_none_or(|basis| basis.leaves.is_empty())
    {
        return false;
    }
    let mut producers = event.proofs.iter().filter_map(|proof| proof.as_producer());
    let Some(producer) = producers.next() else {
        return false;
    };
    if producers.next().is_some() {
        return false;
    }
    let mut admissions = event
        .proofs
        .iter()
        .filter_map(|proof| proof.as_principal_server_admission());
    let Some(_) = admissions.next() else {
        return false;
    };
    if admissions.next().is_some() || event.proofs.len() != 2 {
        return false;
    }
    if event
        .validate_principal_server_admission_binding(digest_suite)
        .is_err()
    {
        return false;
    }
    let Some((controller, fragment)) = producer.verification_method.as_str().split_once('#') else {
        return false;
    };
    let Ok(controller) = arkret_wire::Did::new(controller.to_owned()) else {
        return false;
    };
    arkret_wire::project_did_to_core_id(&controller).is_ok_and(|controller| {
        controller == event.actor_id
            && fragment
                .strip_prefix("ak:device:")
                .is_some_and(|device| !device.is_empty())
    })
}

#[cfg(test)]
mod tests {
    use super::has_self_principal_pcr_device_authorized_shape;

    fn accepted_pcr_device_event() -> arkret_wire::Event {
        let mut event = arkret_wire::test_support::raw_event_at(
            arkret_wire::EventKind::DeviceAuthorize.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: arkret_wire::RealmId::new(format!("ak:realm:A{}", "a".repeat(43)))
                    .unwrap(),
            },
            arkret_wire::DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:soland.example".to_owned()).unwrap(),
            1,
            arkret_wire::Hlc::new("019041000000-0000-00000001").unwrap(),
            serde_json::json!({}),
            "2026-08-14T00:00:00.000Z".parse().unwrap(),
        )
        .unwrap();
        event.seal_basis = Some(arkret_wire::SealBasis {
            leaves: vec![
                arkret_wire::SealId::new(format!("ak:seal:sha256:{}", "1".repeat(64))).unwrap(),
            ],
        });
        let event_digest = arkret_wire::Hash::new(
            event
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap(),
        )
        .unwrap();
        let producer = arkret_wire::ProducerEventProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: arkret_wire::DidUrl::new(
                "did:web:alice.example#ak:device:01904100-0000-7000-8000-a11ce0000001",
            )
            .unwrap(),
            event_digest: event_digest.clone(),
            signer_resolution_evidence_ref: None,
            signer_resolution_evidence_digest: None,
            created_at: event.created_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "producer..signature".to_owned(),
        };
        let admission = arkret_wire::PrincipalServerAdmissionProof {
            kind: arkret_wire::PrincipalServerAdmissionProofKind::PrincipalServerAdmission,
            verification_method: arkret_wire::DidUrl::new("did:web:soland.example#service-key")
                .unwrap(),
            event_digest: event_digest.clone(),
            producer_proof_digest:
                arkret_wire::PrincipalServerAdmissionProof::producer_proof_digest(&producer)
                    .unwrap(),
            producer_verification_method: producer.verification_method.clone(),
            producer_signing_key_did: arkret_wire::DidKey::new("did:key:z6Mkhfixture").unwrap(),
            producer_signer_resolution_evidence_ref: None,
            producer_signer_resolution_evidence_digest: None,
            signer_resolution_evidence_ref: arkret_wire::SignerEvidenceRef::new(format!(
                "ak:signer_evidence:sha256:{}",
                "11".repeat(32)
            ))
            .unwrap(),
            signer_resolution_evidence_digest: arkret_wire::Hash::new(format!(
                "sha256:{}",
                "11".repeat(32)
            ))
            .unwrap(),
            accepted_at: event.created_at,
            jws: "admission..signature".to_owned(),
        };
        event.proofs = vec![producer.into(), admission.into()];
        event
    }

    #[test]
    fn pcr_device_authorized_shape_requires_exact_bound_producer_and_admission() {
        let event = accepted_pcr_device_event();
        assert!(has_self_principal_pcr_device_authorized_shape(
            &event,
            arkret_canonical::DigestSuite::Sha256
        ));

        let mut missing_admission = event.clone();
        missing_admission.proofs.pop();
        assert!(!has_self_principal_pcr_device_authorized_shape(
            &missing_admission,
            arkret_canonical::DigestSuite::Sha256
        ));

        let mut duplicate_producer = event.clone();
        duplicate_producer.proofs.push(event.proofs[0].clone());
        assert!(!has_self_principal_pcr_device_authorized_shape(
            &duplicate_producer,
            arkret_canonical::DigestSuite::Sha256
        ));

        let mut reversed_proofs = event.clone();
        reversed_proofs.proofs.reverse();
        assert!(!has_self_principal_pcr_device_authorized_shape(
            &reversed_proofs,
            arkret_canonical::DigestSuite::Sha256
        ));

        let mut wrong_binding = event;
        if let arkret_wire::EventProof::PrincipalServerAdmission(admission) =
            &mut wrong_binding.proofs[1]
        {
            admission.producer_proof_digest =
                arkret_wire::Hash::new(format!("sha256:{}", "9".repeat(64))).unwrap();
        }
        assert!(!has_self_principal_pcr_device_authorized_shape(
            &wrong_binding,
            arkret_canonical::DigestSuite::Sha256
        ));
    }
}

/// Applet projection mutation committed with a closed Event aggregate.
#[derive(Clone, Debug)]
pub struct AppletRecordCommit {
    pub applet_id: arkret_wire::AppletId,
    /// The accepted managed-actor identity winner used by this installation.
    /// `expected_record=None` is an insert-only first install; `Some` requires
    /// the already accepted winner to remain byte-for-byte unchanged.
    pub identity: AppletIdentityCommit,
    /// Exact durable record observed while validating the aggregate. `None`
    /// means the Applet must not exist and this mutation is an insert.
    pub expected_record: Option<serde_json::Value>,
    pub record: serde_json::Value,
}

#[derive(Clone, Debug)]
pub struct AppletIdentityCommit {
    pub target_principal_server_id: arkret_wire::DidCoreId,
    pub expected_record: Option<serde_json::Value>,
    pub record: serde_json::Value,
}

/// Stable storage coordinate for one effective Applet installation. The
/// canonical scope JSON, rather than an ad-hoc realm/circle concatenation,
/// keeps Realm and Circle installs disjoint and gives every backend the same
/// composite-key derivation.
pub fn applet_effective_scope_key(scope: &arkret_wire::ScopeRef) -> PersistenceResult<String> {
    arkret_canonical::canonical_sha256(scope).map_err(|error| {
        PersistenceError::Conflict(format!(
            "schema_violation: Applet effective_scope is not canonical: {error}"
        ))
    })
}

pub fn applet_effective_scope_key_from_record(
    record: &serde_json::Value,
) -> PersistenceResult<String> {
    let scope = record.get("effective_scope").cloned().ok_or_else(|| {
        PersistenceError::Conflict(
            "schema_violation: durable Applet installation omits effective_scope".to_owned(),
        )
    })?;
    let scope: arkret_wire::ScopeRef = serde_json::from_value(scope).map_err(|error| {
        PersistenceError::Conflict(format!(
            "schema_violation: durable Applet effective_scope is invalid: {error}"
        ))
    })?;
    applet_effective_scope_key(&scope)
}

pub fn applet_id_from_record(record: &serde_json::Value) -> PersistenceResult<&str> {
    record
        .get("applet_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            PersistenceError::Conflict(
                "schema_violation: Applet installation record is missing applet_id".to_owned(),
            )
        })
}

/// Installation records are exact per-scope state only. Reject identity
/// anchors here as well as in the typed HTTP codec and PostgreSQL CHECK so the
/// memory and PostgreSQL adapters cannot drift into copying the accepted
/// identity winner back into every installation.
pub fn validate_applet_installation_record(record: &serde_json::Value) -> PersistenceResult<()> {
    const IDENTITY_FIELDS: &[&str] = &[
        "identity",
        "registry_id",
        "bot_actor_id",
        "bot_actor_principal_server_id",
        "bot_actor_provision_ref",
        "bot_principal_control_realm_id",
        "initial_package",
        "initial_owner_actor_id",
        "initial_effective_scope",
        "initial_registration_event",
        "initial_capability_grant_refs",
        "bot_actor_provision_event",
        "bot_pcr_genesis_event",
        "bot_accountability_grant_event",
        "bot_profile_event",
        "globally_fenced_at",
    ];
    let object = record.as_object().ok_or_else(|| {
        PersistenceError::Conflict(
            "schema_violation: durable Applet installation is not an object".to_owned(),
        )
    })?;
    if let Some(field) = IDENTITY_FIELDS
        .iter()
        .find(|field| object.contains_key(**field))
    {
        return Err(PersistenceError::Conflict(format!(
            "schema_violation: Applet installation contains managed identity field {field}"
        )));
    }
    Ok(())
}

/// Decode the canonical namespace source from a strict durable Applet record.
///
/// The namespace claim table is a transaction-local conflict index, not a
/// second protocol carrier. Every adapter derives it from
/// `record.package.namespaces`; callers cannot supply an independently
/// drifting mirror.
pub fn applet_namespaces_from_record(
    record: &serde_json::Value,
) -> PersistenceResult<arkret_models_integration::AppletWireNamespaces> {
    let namespaces = record
        .pointer("/package/namespaces")
        .cloned()
        .ok_or_else(|| {
            PersistenceError::Conflict(
                "schema_violation: durable Applet record omits package.namespaces".to_owned(),
            )
        })?;
    serde_json::from_value(namespaces).map_err(|error| {
        PersistenceError::Conflict(format!(
            "schema_violation: durable Applet package.namespaces are invalid: {error}"
        ))
    })
}

/// Derive every immutable managed authority pair from the canonical Applet
/// record. The uniqueness table is a transaction index of this set; it never
/// accepts a separately supplied claim list.
pub fn applet_managed_authorities_from_record(
    identity: &serde_json::Value,
    installation: &serde_json::Value,
) -> PersistenceResult<std::collections::BTreeSet<ManagedAuthorityClaim>> {
    let required = |field: &str| {
        identity
            .get(field)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                PersistenceError::Conflict(format!(
                    "schema_violation: durable Applet record omits {field}"
                ))
            })
    };
    let mut authorities = std::collections::BTreeSet::from([ManagedAuthorityClaim {
        actor_id: required("bot_actor_id")?.to_owned(),
        principal_server_id: required("bot_actor_principal_server_id")?.to_owned(),
    }]);
    let ghosts = installation
        .get("ghosts")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            PersistenceError::Conflict(
                "schema_violation: durable Applet record omits ghosts".to_owned(),
            )
        })?;
    for ghost in ghosts {
        let actor_id = ghost
            .get("ghost_actor_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                PersistenceError::Conflict(
                    "schema_violation: durable Applet Ghost omits ghost_actor_id".to_owned(),
                )
            })?;
        let principal_server_id = ghost
            .get("actor_principal_server_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                PersistenceError::Conflict(
                    "schema_violation: durable Applet Ghost omits actor_principal_server_id"
                        .to_owned(),
                )
            })?;
        if !authorities.insert(ManagedAuthorityClaim {
            actor_id: actor_id.to_owned(),
            principal_server_id: principal_server_id.to_owned(),
        }) {
            return Err(PersistenceError::Conflict(
                "applet_managed_authority_conflict".to_owned(),
            ));
        }
    }
    Ok(authorities)
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ManagedAuthorityClaim {
    pub actor_id: String,
    pub principal_server_id: String,
}

/// All durable writes produced by accepting a closed multi-Event aggregate.
#[derive(Clone, Debug)]
pub struct EventBatchCommitRequest {
    pub events: Vec<EventCommitRequest>,
    /// One native-agent act-on-behalf approval nonce consumed by an Event in
    /// this batch. The ledger row and Event are committed atomically.
    pub agent_approval_nonce: Option<AgentApprovalNonceCommit>,
    /// One moderation franking nonce consumed by a report Event in this
    /// batch. The ledger write is inseparable from the report Event: a failed
    /// commit consumes nothing, and a concurrent replay can commit at most
    /// once across processes.
    pub franking_replay_nonce: Option<FrankingReplayNonceCommit>,
    pub applet_record: Option<AppletRecordCommit>,
    pub applet_authoring_preview: Option<AppletAuthoringPreviewCommit>,
    pub agent_membership_cascade: Option<crate::AgentMembershipCascadeCommit>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrankingReplayNonceCommit {
    pub realm_id: String,
    pub received_by: arkret_identifiers::DidCoreId,
    pub replay_nonce: String,
    pub report_event_id: String,
    pub consumed_at: DateTime<Utc>,
}

/// Soland's local retention default for a consumed franking nonce. The wire
/// protocol requires a finite window but does not assign its duration.
pub const LOCAL_FRANKING_REPLAY_NONCE_TTL_SECONDS: i64 = 24 * 60 * 60;

/// Soland's local active-row ceiling per `(realm_id, received_by)` scope.
/// Capacity exhaustion fails closed instead of evicting an active nonce.
pub const LOCAL_FRANKING_REPLAY_NONCE_MAX_ACTIVE_PER_SCOPE: usize = 4096;

pub fn franking_replay_nonce_expires_at(
    consumed_at: DateTime<Utc>,
) -> PersistenceResult<DateTime<Utc>> {
    consumed_at
        .checked_add_signed(chrono::TimeDelta::seconds(
            LOCAL_FRANKING_REPLAY_NONCE_TTL_SECONDS,
        ))
        .ok_or_else(|| {
            PersistenceError::Conflict(
                "schema_violation: franking nonce expiry overflows canonical time".to_owned(),
            )
        })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentApprovalNonceCommit {
    pub agent_id: String,
    pub authorization_ref: String,
    pub request_id: String,
    pub approval_nonce: String,
    pub event_id: String,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: DateTime<Utc>,
}

/// Refuse an approval nonce ledger row unless the same batch contains the
/// exact Event and projected operation that admission validated.
pub fn validate_agent_approval_nonce_commit(
    events: &[EventCommitRequest],
    commit: Option<&AgentApprovalNonceCommit>,
) -> PersistenceResult<()> {
    let Some(commit) = commit else {
        return Ok(());
    };
    if commit.expires_at <= commit.consumed_at {
        return Err(PersistenceError::Conflict(
            "schema_violation: expired agent approval nonce cannot be consumed".to_owned(),
        ));
    }
    let Some(event) = events
        .iter()
        .find(|request| request.event.event_id == commit.event_id)
    else {
        return Err(PersistenceError::Conflict(
            "schema_violation: agent approval nonce is not bound to an Event in the batch"
                .to_owned(),
        ));
    };
    let event_agent_id = event
        .event
        .envelope
        .pointer("/unsigned/agent_context/agent_id")
        .and_then(Value::as_str);
    let matches = event.projections.iter().any(|projection| {
        projection.event_id == commit.event_id
            && projection
                .payload
                .get("authorization_ref")
                .and_then(Value::as_str)
                == Some(commit.authorization_ref.as_str())
            && projection
                .payload
                .get("approval_request_id")
                .or_else(|| projection.payload.get("request_id"))
                .and_then(Value::as_str)
                == Some(commit.request_id.as_str())
            && projection
                .payload
                .get("approval_nonce")
                .and_then(Value::as_str)
                == Some(commit.approval_nonce.as_str())
            && (projection
                .payload
                .pointer("/agent_context/agent_id")
                .or_else(|| {
                    projection
                        .payload
                        .pointer("/provenance/agent_context/agent_id")
                })
                .and_then(Value::as_str)
                == Some(commit.agent_id.as_str())
                || event_agent_id == Some(commit.agent_id.as_str()))
    });
    if !matches {
        return Err(PersistenceError::Conflict(
            "schema_violation: agent approval nonce does not match its Event operation".to_owned(),
        ));
    }
    Ok(())
}

/// Refuse a nonce ledger row unless the same batch contains the exact report
/// Event and its signed franking payload. Persistence repeats this binding so
/// a future caller cannot accidentally turn the ledger into an unscoped
/// uniqueness service.
pub fn validate_franking_replay_nonce_commit(
    events: &[EventCommitRequest],
    commit: Option<&FrankingReplayNonceCommit>,
) -> PersistenceResult<()> {
    let Some(commit) = commit else {
        return Ok(());
    };
    let Some(report) = events
        .iter()
        .find(|request| request.event.event_id == commit.report_event_id)
    else {
        return Err(PersistenceError::Conflict(
            "schema_violation: franking nonce is not bound to a report Event in the batch"
                .to_owned(),
        ));
    };
    if report.event.kind != arkret_wire::EventKind::SelfModerationReport.as_str()
        || report.event.realm_id.as_deref() != Some(commit.realm_id.as_str())
        || report
            .event
            .envelope
            .pointer("/payload/franking_proof/received_by")
            .and_then(Value::as_str)
            != Some(commit.received_by.as_str())
        || report
            .event
            .envelope
            .pointer("/payload/franking_proof/replay_nonce")
            .and_then(Value::as_str)
            != Some(commit.replay_nonce.as_str())
    {
        return Err(PersistenceError::Conflict(
            "schema_violation: franking nonce does not match its report Event payload".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct AppletAuthoringPreviewCommit {
    pub subject_key: String,
    pub request_digest: String,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EventCommitOutcome {
    pub event_inserted: bool,
    pub projections_inserted: usize,
    pub outbox_inserted: usize,
}

#[async_trait]
pub trait EventCommitUnitOfWork: Send + Sync {
    async fn commit_event(
        &self,
        request: EventCommitRequest,
    ) -> PersistenceResult<EventCommitOutcome>;

    async fn commit_event_batch(
        &self,
        request: EventBatchCommitRequest,
    ) -> PersistenceResult<EventCommitOutcome>;
}

/// Re-check the Realm-scoped actor sequence and fork caps inside the durable
/// commit boundary. Route-level validation gives precise protocol errors;
/// this guard prevents another process from invalidating that decision before
/// the canonical insert commits.
#[doc(hidden)]
pub fn validate_actor_scope_commit<'a>(
    existing: impl IntoIterator<Item = &'a CanonicalEventRecord>,
    event: &CanonicalEventRecord,
) -> PersistenceResult<()> {
    let Some(realm_id) = event.realm_id.as_deref() else {
        return Err(crate::PersistenceError::Conflict(
            "schema_violation: missing realm_id".to_owned(),
        ));
    };
    let scoped = existing
        .into_iter()
        .filter(|record| {
            record.actor_id == event.actor_id && record.realm_id.as_deref() == Some(realm_id)
        })
        .collect::<Vec<_>>();
    if let Some(max_seq) = scoped.iter().map(|record| record.actor_seq).max() {
        if event.actor_seq < max_seq {
            return Err(crate::PersistenceError::Conflict("cas_conflict".to_owned()));
        }
        if event.actor_seq > max_seq.saturating_add(1) {
            return Err(crate::PersistenceError::Conflict(
                "schema_violation: actor_seq gap".to_owned(),
            ));
        }
    } else if event.actor_seq != 0 {
        return Err(crate::PersistenceError::Conflict(
            "schema_violation: actor genesis must use seq 0".to_owned(),
        ));
    }

    let same_height = scoped
        .iter()
        .copied()
        .filter(|record| record.actor_seq == event.actor_seq)
        .collect::<Vec<_>>();
    if same_height.len() >= arkret_wire::MAX_ACTOR_SEQ_TOTAL_SIBLINGS {
        return Err(crate::PersistenceError::Conflict(
            "fork_quarantine: actor sequence sibling limit".to_owned(),
        ));
    }
    let prev_refs = event
        .envelope
        .get("prev_refs")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|value| serde_json::from_value(value.clone()).ok())
        .collect::<Vec<_>>();
    let digest = arkret_wire::prev_frontier_digest(&prev_refs)
        .map_err(|error| crate::PersistenceError::Conflict(format!("schema_violation: {error}")))?;
    let same_bucket = same_height
        .iter()
        .filter(|record| {
            let refs = record
                .envelope
                .get("prev_refs")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|value| serde_json::from_value(value.clone()).ok())
                .collect::<Vec<_>>();
            arkret_wire::prev_frontier_digest(&refs).ok().as_deref() == Some(digest.as_str())
        })
        .count();
    if same_bucket >= arkret_wire::MAX_ACTOR_SEQ_SIBLINGS {
        return Err(crate::PersistenceError::Conflict(
            "fork_quarantine: actor predecessor bucket limit".to_owned(),
        ));
    }
    Ok(())
}
