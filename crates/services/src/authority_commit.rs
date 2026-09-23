//! Current governance-Station application boundary.

use arkret_models_collaboration::authority_commit::{
    DirectConversationFoundingAcceptanceOutcome, DirectConversationFoundingFederationSubmission,
    DirectConversationFoundingUnitSubmission, MembershipCompensationAcceptanceOutcome,
    MembershipCompensationFederationSubmission, MembershipCompensationUnitSubmission,
    OrdinaryRealmBootstrapAcceptanceOutcome, OrdinaryRealmBootstrapUnitSubmission,
    PeerAuthoritySubmitOutcome, PeerAuthoritySubmitRequest, PeerCommittedReplicationOutcome,
    PeerCommittedReplicationRequest, PeerRegisteredAtomicUnit, PeerRegisteredAtomicUnitOutcome,
    PeerRegisteredAtomicUnitOutcomeValue, SelfAuthoritySubmitOutcome, SelfAuthoritySubmitRequest,
};
use arkret_models_collaboration::principal_operations::PcrGenesisAdmissionInput;
use arkret_wire::{
    AuthorityBundleRequest, AuthorityHandoffRequest, AuthoritySubmitOutcome, CommitStreamHead,
    CommitStreamRef, DetachedSignatureContext, DidCoreId, DidUrl, Event, EventAdmissionSubmission,
    MlsCommitSubmission, RealmAuthorityBundle, RealmAuthorityCurrentAssertion,
    RealmAuthorityHandoff, RealmAuthorityTransition, RealmCommit, RealmCommitId,
    RealmStateSnapshot, StreamScanDirection, StreamScanOutcome, StreamScanRequest,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use serde::Serialize;
use soland_storage::{
    AuthorityCommitStore, AuthorityCommitTransaction, AuthorityCommitWriteOutcome,
    CurrentRealmAuthority, OrdinaryRealmBootstrapCommitOutcome, OrdinaryRealmBootstrapCommitUnit,
    PcrGenesisCommitOutcome, PcrGenesisCommitUnit, QueuedEventRecord, SelfProducerCommitGuard,
};

use crate::persistence::PersistenceHandle;
use crate::{ServiceError, ServiceResult};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorityEventAdmissionOutcome {
    Committed(RealmCommit),
    Duplicate(RealmCommit),
    NotCurrentAuthority,
}

#[derive(Serialize)]
struct RealmCommitIdentityBody<'a> {
    realm_id: &'a arkret_wire::RealmId,
    stream_ref: &'a CommitStreamRef,
    stream_position: u64,
    previous_commit_ref: &'a Option<RealmCommitId>,
    event_ref: &'a arkret_wire::EventId,
    governance_generation: u64,
    authority_ref: &'a arkret_wire::RealmCommitAuthorityRef,
    committed_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct RealmCommitUnsignedBody<'a> {
    commit_id: &'a RealmCommitId,
    realm_id: &'a arkret_wire::RealmId,
    stream_ref: &'a CommitStreamRef,
    stream_position: u64,
    previous_commit_ref: &'a Option<RealmCommitId>,
    event_ref: &'a arkret_wire::EventId,
    governance_generation: u64,
    authority_ref: &'a arkret_wire::RealmCommitAuthorityRef,
    committed_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct RealmSnapshotIdentityBody<'a> {
    realm_id: &'a arkret_wire::RealmId,
    governance_generation: u64,
    visible_stream_heads: &'a [CommitStreamHead],
    current_state_entries: &'a [arkret_wire::TypedCurrentResult],
    retention_and_history_floor: &'a arkret_wire::RetentionAndHistoryFloor,
    created_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct RealmSnapshotUnsignedBody<'a> {
    snapshot_id: &'a arkret_wire::RealmSnapshotId,
    realm_id: &'a arkret_wire::RealmId,
    governance_generation: u64,
    visible_stream_heads: &'a [CommitStreamHead],
    current_state_entries: &'a [arkret_wire::TypedCurrentResult],
    retention_and_history_floor: &'a arkret_wire::RetentionAndHistoryFloor,
    created_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct RealmAuthorityAssertionUnsignedBody<'a> {
    realm_id: &'a arkret_wire::RealmId,
    current_generation: u64,
    current_service_id: &'a DidCoreId,
    last_handoff_ref: &'a Option<arkret_wire::RealmAuthorityHandoffId>,
    realm_stream_head: &'a CommitStreamHead,
    nonce: &'a arkret_wire::Base64UrlString,
    #[serde(serialize_with = "arkret_wire::serde_helpers::serialize_canonical_timestamp")]
    expires_at: DateTime<Utc>,
}

pub fn build_signed_realm_state_snapshot(
    material: &soland_storage::RealmStateSnapshotMaterial,
    verification_method: DidUrl,
    signing_key: &SigningKey,
    created_at: DateTime<Utc>,
) -> ServiceResult<RealmStateSnapshot> {
    if material.visible_stream_heads.is_empty()
        || !material
            .visible_stream_heads
            .windows(2)
            .all(|pair| pair[0].stream_ref < pair[1].stream_ref)
    {
        return Err(ServiceError::SchemaViolation(
            "Realm snapshot requires sorted, unique visible stream heads".to_owned(),
        ));
    }
    let created_at = arkret_canonical::normalize_timestamp_canonical(created_at);
    let identity = RealmSnapshotIdentityBody {
        realm_id: &material.realm_id,
        governance_generation: material.governance_generation,
        visible_stream_heads: &material.visible_stream_heads,
        current_state_entries: &material.current_state_entries,
        retention_and_history_floor: &material.retention_and_history_floor,
        created_at,
    };
    let identity_bytes = arkret_canonical::canonical_json_bytes(&identity)
        .map_err(|error| ServiceError::Internal(error.to_string()))?;
    let snapshot_id =
        arkret_wire::RealmSnapshotId::from_digest(arkret_canonical::sha256_bytes(&identity_bytes));
    let unsigned = RealmSnapshotUnsignedBody {
        snapshot_id: &snapshot_id,
        realm_id: &material.realm_id,
        governance_generation: material.governance_generation,
        visible_stream_heads: &material.visible_stream_heads,
        current_state_entries: &material.current_state_entries,
        retention_and_history_floor: &material.retention_and_history_floor,
        created_at,
    };
    let signature = arkret_signatures::detached_object::sign_detached_object(
        &unsigned,
        DetachedSignatureContext::RealmSnapshot,
        verification_method,
        created_at,
        signing_key,
    )
    .map_err(|error| ServiceError::Internal(error.to_string()))?;
    Ok(RealmStateSnapshot {
        snapshot_id,
        realm_id: material.realm_id.clone(),
        governance_generation: material.governance_generation,
        visible_stream_heads: material.visible_stream_heads.clone(),
        current_state_entries: material.current_state_entries.clone(),
        retention_and_history_floor: material.retention_and_history_floor.clone(),
        created_at,
        signature,
    })
}

/// Verify both genesis Event signatures against keys pinned by the exact
/// registration anchor and founding device descriptor, never current DID
/// resolution. The short-lived control-proof time window is checked by the
/// authenticated peer ingress before a fresh admission.
fn validate_pcr_genesis_producer_proofs(
    submission: &PcrGenesisAdmissionInput,
) -> ServiceResult<()> {
    use arkret_models_collaboration::events_payloads::DeviceAuthorizePayload;
    use arkret_models_identity::PrincipalRegistrationAnchor;

    let invalid = |detail: String| ServiceError::SchemaViolation(detail);
    let anchor = arkret_identity::validate_principal_registration_anchor(
        &submission.principal_registration_anchor,
    )
    .map_err(|error| invalid(format!("PCR registration anchor is invalid: {error}")))?;
    arkret_signatures::webvh::verify_identity_creation_control_proof(
        &anchor,
        &submission.identity_creation_control_proof,
    )
    .map_err(|error| invalid(format!("PCR identity creation proof is invalid: {error}")))?;
    let PrincipalRegistrationAnchor::WebvhRegistration {
        registration_did_operation,
        ..
    } = &submission.principal_registration_anchor;
    arkret_signatures::webvh::verify_registration_did_evidence_draft(
        registration_did_operation,
        &submission.registration_did_evidence.draft(),
    )
    .map_err(|error| {
        invalid(format!(
            "PCR frozen registration evidence is invalid: {error}"
        ))
    })?;

    let create = submission.genesis_unit.create();
    let authorize = submission.genesis_unit.founding_authorize();
    let device: DeviceAuthorizePayload = serde_json::from_value(serde_json::Value::Object(
        authorize.payload.clone().into_iter().collect(),
    ))
    .map_err(|error| invalid(format!("PCR founding device payload is invalid: {error}")))?;
    arkret_signatures::verify_device_authorize_possession(
        &device,
        &arkret_wire::AccountId::new(
            submission.principal_id.clone(),
            submission.account_authority_id.clone(),
        ),
    )
    .map_err(|error| {
        invalid(format!(
            "PCR founding device possession is invalid: {error}"
        ))
    })?;

    let root_key = arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
        value: anchor.root_public_key_multibase.clone(),
    };
    let device_multibase = device
        .device_public_key_did
        .as_str()
        .strip_prefix("did:key:")
        .ok_or_else(|| invalid("PCR founding device key is not did:key".to_owned()))?;
    let device_key = arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
        value: device_multibase.to_owned(),
    };
    let root_method = format!(
        "did:key:{}#{}",
        anchor.root_public_key_multibase, anchor.root_public_key_multibase
    );
    let device_method = format!("{}#{}", submission.did, device.device_id);
    for (event, expected_method, key) in [
        (create, root_method.as_str(), &root_key),
        (authorize, device_method.as_str(), &device_key),
    ] {
        let proof = event
            .producer_proof
            .as_ref()
            .ok_or_else(|| invalid("PCR genesis Event lacks its producer proof".to_owned()))?;
        if proof.verification_method.as_str() != expected_method {
            return Err(invalid(
                "PCR genesis producer method differs from its pinned key".to_owned(),
            ));
        }
        let bytes = arkret_signatures::EventProofBuilder::new()
            .envelope_bytes(event)
            .map_err(|error| invalid(format!("PCR Event canonicalization failed: {error}")))?;
        arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
            proof,
            &bytes,
            &event.actor_id,
            key,
            arkret_canonical::DigestSuite::Sha256,
        )
        .map_err(|error| invalid(format!("PCR Event producer signature is invalid: {error}")))?;
    }
    Ok(())
}

fn build_signed_event_commit(
    event: &Event,
    authority: &CurrentRealmAuthority,
    head: Option<&CommitStreamHead>,
    verification_method: DidUrl,
    signing_key: &SigningKey,
    committed_at: DateTime<Utc>,
) -> ServiceResult<RealmCommit> {
    let stream_ref = CommitStreamRef::from_scope(&event.scope_ref, Some(event.realm_id.clone()))
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    if head.is_some_and(|value| value.stream_ref != stream_ref) {
        return Err(ServiceError::Internal(
            "authority store returned a head for the wrong stream".to_owned(),
        ));
    }
    let (stream_position, previous_commit_ref) = match head {
        Some(head) => (
            head.stream_position.checked_add(1).ok_or_else(|| {
                ServiceError::Internal("authority stream position overflow".to_owned())
            })?,
            Some(head.commit_id.clone()),
        ),
        None => (0, None),
    };
    let committed_at = arkret_canonical::normalize_timestamp_canonical(committed_at);
    let identity_body = RealmCommitIdentityBody {
        realm_id: &event.realm_id,
        stream_ref: &stream_ref,
        stream_position,
        previous_commit_ref: &previous_commit_ref,
        event_ref: &event.event_id,
        governance_generation: authority.generation,
        authority_ref: &authority.authority_ref,
        committed_at,
    };
    // `commit_id` is the typed content address of the closed commit body.
    // Like every self-identifying object, its identity preimage excludes the
    // identity field itself as well as the detached signature.
    let identity_bytes = arkret_canonical::canonical_json_bytes(&identity_body)
        .map_err(|error| ServiceError::Internal(error.to_string()))?;
    let commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(&identity_bytes));
    let unsigned_body = RealmCommitUnsignedBody {
        commit_id: &commit_id,
        realm_id: &event.realm_id,
        stream_ref: &stream_ref,
        stream_position,
        previous_commit_ref: &previous_commit_ref,
        event_ref: &event.event_id,
        governance_generation: authority.generation,
        authority_ref: &authority.authority_ref,
        committed_at,
    };
    let signature = arkret_signatures::detached_object::sign_detached_object(
        &unsigned_body,
        DetachedSignatureContext::RealmCommit,
        verification_method,
        committed_at,
        signing_key,
    )
    .map_err(|error| ServiceError::Internal(error.to_string()))?;
    let commit = RealmCommit {
        commit_id,
        realm_id: event.realm_id.clone(),
        stream_ref,
        stream_position,
        previous_commit_ref,
        event_ref: event.event_id.clone(),
        governance_generation: authority.generation,
        authority_ref: authority.authority_ref.clone(),
        committed_at,
        signature,
    };
    commit
        .validate_shape()
        .map_err(|error| ServiceError::Internal(error.to_string()))?;
    Ok(commit)
}

/// Durable queued-to-committed lifecycle used by the governance Station.
///
/// Signature verification, policy evaluation, MLS installation, and commit
/// signing happen before [`Self::install_commit`]. The store then performs one
/// atomic authority-generation check, stream append, Event state transition,
/// and Welcome enqueue.
#[derive(Clone)]
pub struct AuthorityCommitApplication {
    persistence: PersistenceHandle,
    recipient_queue_capacity: usize,
}

impl AuthorityCommitApplication {
    pub fn new(persistence: PersistenceHandle, recipient_queue_capacity: usize) -> Self {
        Self {
            persistence,
            recipient_queue_capacity,
        }
    }

    fn store(&self) -> &dyn AuthorityCommitStore {
        self.persistence.authority_commit_store()
    }

    pub async fn install_genesis_authority(
        &self,
        authority: &CurrentRealmAuthority,
    ) -> ServiceResult<()> {
        self.store().install_genesis_authority(authority).await?;
        Ok(())
    }

    /// Optional authoring preparation may read current membership only while
    /// this service is the verified governing Station. This read grants no
    /// Event authority; admission still checks the current commit cut.
    pub async fn local_current_member_joined(
        &self,
        realm_id: &arkret_wire::RealmId,
        member: &arkret_wire::ActorId,
        service_id: &DidCoreId,
    ) -> ServiceResult<bool> {
        Ok(self
            .store()
            .local_current_member_joined(realm_id, member, service_id)
            .await?)
    }

    pub async fn queue_event(&self, event: &Event, queued_at: DateTime<Utc>) -> ServiceResult<()> {
        event.validate_for_submit_structural().map_err(|error| {
            crate::ServiceError::SchemaViolation(format!("invalid producer Event: {error}"))
        })?;
        self.store().queue_event(event, queued_at).await?;
        Ok(())
    }

    pub async fn queued_event(
        &self,
        event_id: &arkret_wire::EventId,
    ) -> ServiceResult<Option<QueuedEventRecord>> {
        Ok(self.store().queued_event(event_id).await?)
    }

    pub async fn install_commit(
        &self,
        transaction: &AuthorityCommitTransaction,
    ) -> ServiceResult<AuthorityCommitWriteOutcome> {
        // The service configuration, never the producer's submission, sets
        // the queue bound for a Commit carrying recipient-private Welcome.
        let mut transaction = transaction.clone();
        transaction.recipient_queue_capacity = self.recipient_queue_capacity;
        transaction.validate().map_err(|error| {
            crate::ServiceError::SchemaViolation(format!("invalid authority transaction: {error}"))
        })?;
        Ok(self.store().commit_transaction(&transaction).await?)
    }

    /// Install an ordinary Realm genesis unit through one durable authority
    /// transaction. The caller must first perform session, producer-proof,
    /// policy and MLS validation and construct every signed Commit; the store
    /// enforces the ordered unit and exact-byte replay under one DB lock.
    pub async fn admit_ordinary_realm_bootstrap_unit(
        &self,
        unit: &OrdinaryRealmBootstrapCommitUnit,
        queued_at: DateTime<Utc>,
    ) -> ServiceResult<OrdinaryRealmBootstrapCommitOutcome> {
        unit.validate().map_err(|error| {
            ServiceError::SchemaViolation(format!("invalid ordinary Realm bootstrap unit: {error}"))
        })?;
        Ok(self
            .store()
            .admit_ordinary_realm_bootstrap_unit(unit, queued_at)
            .await?)
    }

    /// Atomically publish both PCR genesis Events and Commits, the identity
    /// resolution current result and the founding device current result.
    pub async fn admit_pcr_genesis_unit(
        &self,
        unit: &PcrGenesisCommitUnit,
        queued_at: DateTime<Utc>,
    ) -> ServiceResult<PcrGenesisCommitOutcome> {
        unit.validate().map_err(|error| {
            ServiceError::SchemaViolation(format!("invalid PCR genesis unit: {error}"))
        })?;
        Ok(self.store().admit_pcr_genesis_unit(unit, queued_at).await?)
    }

    /// Resolve an exact durable retry before checking a now-expired producer
    /// proof. This grants no fresh admission: altered bytes or a reused key
    /// fail as a duplicate conflict in the same receipt ledger as the writer.
    pub async fn pcr_genesis_replay(
        &self,
        submission: &PcrGenesisAdmissionInput,
        exact_request_body: &[u8],
    ) -> ServiceResult<
        Option<arkret_models_collaboration::principal_operations::PcrGenesisAdmissionResult>,
    > {
        submission
            .validate()
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        if serde_json::from_slice::<PcrGenesisAdmissionInput>(exact_request_body)
            .ok()
            .as_ref()
            != Some(submission)
        {
            return Err(ServiceError::SchemaViolation(
                "PCR genesis exact request bytes differ from parsed submission".to_owned(),
            ));
        }
        Ok(self
            .store()
            .pcr_genesis_replay(submission, exact_request_body)
            .await?)
    }

    /// Prepare the two signed Station Commits before entering the durable unit.
    /// The caller authenticates the Account Authority relay and validates both
    /// producer proofs before invoking the matching admission method.
    pub fn prepare_pcr_genesis_unit(
        &self,
        submission: PcrGenesisAdmissionInput,
        exact_request_body: Vec<u8>,
        authority: &CurrentRealmAuthority,
        verification_method: DidUrl,
        signing_key: &SigningKey,
        committed_at: DateTime<Utc>,
    ) -> ServiceResult<PcrGenesisCommitUnit> {
        submission
            .validate()
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        validate_pcr_genesis_producer_proofs(&submission)?;
        let events = [
            submission.genesis_unit.create(),
            submission.genesis_unit.founding_authorize(),
        ];
        let first = build_signed_event_commit(
            events[0],
            authority,
            None,
            verification_method.clone(),
            signing_key,
            committed_at,
        )?;
        let first_head = CommitStreamHead {
            stream_ref: first.stream_ref.clone(),
            stream_position: first.stream_position,
            commit_id: first.commit_id.clone(),
        };
        let second = build_signed_event_commit(
            events[1],
            authority,
            Some(&first_head),
            verification_method,
            signing_key,
            committed_at,
        )?;
        let transactions = [(events[0], first), (events[1], second)].map(|(event, commit)| {
            AuthorityCommitTransaction {
                expected_authority: authority.clone(),
                event: event.clone(),
                commit,
                mls_state: None,
                welcomes: Vec::new(),
                recipient_queue_capacity: self.recipient_queue_capacity,
            }
        });
        let unit = PcrGenesisCommitUnit {
            submission,
            exact_request_body,
            transactions,
        };
        unit.validate()
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        Ok(unit)
    }

    /// Prepare the complete ordered ordinary Realm bootstrap without writing
    /// anything. The HTTP authority adapter must first verify every producer
    /// proof and authorization at one authority cut, then pass this exact unit
    /// to `admit_ordinary_realm_bootstrap_unit` for atomic persistence.
    pub fn prepare_ordinary_realm_bootstrap_unit(
        &self,
        submission: OrdinaryRealmBootstrapUnitSubmission,
        exact_request_body: Vec<u8>,
        authority: &CurrentRealmAuthority,
        verification_method: DidUrl,
        signing_key: &SigningKey,
        committed_at: DateTime<Utc>,
    ) -> ServiceResult<OrdinaryRealmBootstrapCommitUnit> {
        submission
            .validate()
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        let genesis = &submission.events[0].event;
        if authority.realm_id != genesis.realm_id
            || authority.generation != 0
            || authority.authority_ref
                != arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                    genesis.event_id.clone(),
                )
        {
            return Err(ServiceError::SchemaViolation(
                "ordinary Realm bootstrap authority must be the genesis Event at generation zero"
                    .to_owned(),
            ));
        }
        let mut previous_head: Option<CommitStreamHead> = None;
        let mut transactions = Vec::with_capacity(submission.events.len());
        for submitted in &submission.events {
            let event = &submitted.event;
            if event.scope_ref
                != (arkret_wire::ScopeRef::Realm {
                    realm_id: genesis.realm_id.clone(),
                })
            {
                return Err(ServiceError::SchemaViolation(
                    "ordinary Realm bootstrap Event must use the Realm stream".to_owned(),
                ));
            }
            let commit = build_signed_event_commit(
                event,
                authority,
                previous_head.as_ref(),
                verification_method.clone(),
                signing_key,
                committed_at,
            )?;
            previous_head = Some(CommitStreamHead {
                stream_ref: commit.stream_ref.clone(),
                stream_position: commit.stream_position,
                commit_id: commit.commit_id.clone(),
            });
            transactions.push(AuthorityCommitTransaction {
                expected_authority: authority.clone(),
                event: event.clone(),
                commit,
                mls_state: None,
                welcomes: Vec::new(),
                recipient_queue_capacity: self.recipient_queue_capacity,
            });
        }
        let unit = OrdinaryRealmBootstrapCommitUnit {
            submission,
            exact_request_body,
            transactions,
        };
        unit.validate()
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        Ok(unit)
    }

    /// Sign the two PCR recovery Commits without publishing them. The caller
    /// passes this closed pair to `SecurityTransactionStore::commit_recovery_unit`;
    /// that one storage transaction rechecks the predecessor and installs both.
    pub fn prepare_recovery_unit_commits(
        &self,
        events: &[Event; 2],
        authority: &CurrentRealmAuthority,
        predecessor: &CommitStreamHead,
        verification_method: DidUrl,
        signing_key: &SigningKey,
        committed_at: DateTime<Utc>,
    ) -> ServiceResult<[AuthorityCommitTransaction; 2]> {
        let expected_stream = CommitStreamRef::Realm {
            realm_id: authority.realm_id.clone(),
        };
        if predecessor.stream_ref != expected_stream
            || events[0].kind != arkret_wire::EventKind::DeviceReanchor
            || events[1].kind != arkret_wire::EventKind::DeviceAuthorize
            || events.iter().any(|event| {
                event.realm_id != authority.realm_id
                    || event.scope_ref.realm_id() != &authority.realm_id
            })
        {
            return Err(ServiceError::SchemaViolation(
                "recovery Commit pair is not the exact PCR Realm Event unit".to_owned(),
            ));
        }
        let first = build_signed_event_commit(
            &events[0],
            authority,
            Some(predecessor),
            verification_method.clone(),
            signing_key,
            committed_at,
        )?;
        let first_head = CommitStreamHead {
            stream_ref: expected_stream,
            stream_position: first.stream_position,
            commit_id: first.commit_id.clone(),
        };
        let second = build_signed_event_commit(
            &events[1],
            authority,
            Some(&first_head),
            verification_method,
            signing_key,
            committed_at,
        )?;
        Ok([
            AuthorityCommitTransaction {
                expected_authority: authority.clone(),
                event: events[0].clone(),
                commit: first,
                mls_state: None,
                welcomes: Vec::new(),
                recipient_queue_capacity: self.recipient_queue_capacity,
            },
            AuthorityCommitTransaction {
                expected_authority: authority.clone(),
                event: events[1].clone(),
                commit: second,
                mls_state: None,
                welcomes: Vec::new(),
                recipient_queue_capacity: self.recipient_queue_capacity,
            },
        ])
    }

    /// Admit one already-validated producer Event as this Realm's current
    /// governance Station.
    ///
    /// The storage call is deliberately a single queue+commit transaction.
    /// A failed authority/head CAS therefore cannot leave a queued Event that
    /// a later path might mistake for accepted state.
    pub async fn admit_event(
        &self,
        event: &Event,
        local_service_id: &DidCoreId,
        verification_method: DidUrl,
        signing_key: &SigningKey,
        committed_at: DateTime<Utc>,
    ) -> ServiceResult<AuthorityEventAdmissionOutcome> {
        self.admit_event_with_guard(
            event,
            local_service_id,
            verification_method,
            signing_key,
            committed_at,
            None,
        )
        .await
    }

    pub async fn admit_self_event(
        &self,
        event: &Event,
        local_service_id: &DidCoreId,
        verification_method: DidUrl,
        signing_key: &SigningKey,
        committed_at: DateTime<Utc>,
        guard: &SelfProducerCommitGuard,
    ) -> ServiceResult<AuthorityEventAdmissionOutcome> {
        self.admit_event_with_guard(
            event,
            local_service_id,
            verification_method,
            signing_key,
            committed_at,
            Some(guard),
        )
        .await
    }

    async fn admit_event_with_guard(
        &self,
        event: &Event,
        local_service_id: &DidCoreId,
        verification_method: DidUrl,
        signing_key: &SigningKey,
        committed_at: DateTime<Utc>,
        guard: Option<&SelfProducerCommitGuard>,
    ) -> ServiceResult<AuthorityEventAdmissionOutcome> {
        event.validate_for_submit_structural().map_err(|error| {
            ServiceError::SchemaViolation(format!("invalid producer Event: {error}"))
        })?;
        if let Some(record) = self.store().committed_event(&event.event_id).await? {
            if record.event != *event {
                return Err(ServiceError::Conflict(
                    "event_id is already committed with different canonical content".to_owned(),
                ));
            }
            return Ok(AuthorityEventAdmissionOutcome::Duplicate(record.commit));
        }
        let Some(authority) = self.store().current_authority(&event.realm_id).await? else {
            return Ok(AuthorityEventAdmissionOutcome::NotCurrentAuthority);
        };
        if &authority.service_id != local_service_id {
            return Ok(AuthorityEventAdmissionOutcome::NotCurrentAuthority);
        }
        let stream_ref =
            CommitStreamRef::from_scope(&event.scope_ref, Some(event.realm_id.clone()))
                .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        let head = self.store().stream_head(&stream_ref).await?;
        let commit = build_signed_event_commit(
            event,
            &authority,
            head.as_ref(),
            verification_method,
            signing_key,
            committed_at,
        )?;
        let transaction = AuthorityCommitTransaction {
            expected_authority: authority,
            event: event.clone(),
            commit: commit.clone(),
            mls_state: None,
            welcomes: Vec::new(),
            recipient_queue_capacity: self.recipient_queue_capacity,
        };
        transaction.validate().map_err(|error| {
            ServiceError::SchemaViolation(format!("invalid authority transaction: {error}"))
        })?;
        let write = if let Some(guard) = guard {
            self.store()
                .admit_self_event_transaction(&transaction, guard, committed_at)
                .await?
        } else {
            self.store()
                .admit_event_transaction(&transaction, committed_at)
                .await?
        };
        match write {
            AuthorityCommitWriteOutcome::Committed => {
                Ok(AuthorityEventAdmissionOutcome::Committed(commit))
            }
            AuthorityCommitWriteOutcome::Duplicate => {
                let record = self
                    .store()
                    .committed_event(&event.event_id)
                    .await?
                    .ok_or_else(|| {
                        ServiceError::Internal(
                            "duplicate authority admission has no durable committed Event"
                                .to_owned(),
                        )
                    })?;
                if record.event != *event {
                    return Err(ServiceError::Conflict(
                        "event_id is already committed with different canonical content".to_owned(),
                    ));
                }
                Ok(AuthorityEventAdmissionOutcome::Duplicate(record.commit))
            }
            AuthorityCommitWriteOutcome::StaleAuthority(_) => {
                Ok(AuthorityEventAdmissionOutcome::NotCurrentAuthority)
            }
        }
    }

    pub async fn current_authority(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> ServiceResult<Option<CurrentRealmAuthority>> {
        Ok(self.store().current_authority(realm_id).await?)
    }

    pub async fn stream_head(
        &self,
        stream_ref: &CommitStreamRef,
    ) -> ServiceResult<Option<CommitStreamHead>> {
        Ok(self.store().stream_head(stream_ref).await?)
    }

    pub async fn realm_stream_heads(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> ServiceResult<Vec<CommitStreamHead>> {
        Ok(self.store().realm_stream_heads(realm_id).await?)
    }

    pub async fn committed_event(
        &self,
        event_id: &arkret_wire::EventId,
    ) -> ServiceResult<Option<soland_storage::CommittedEventRecord>> {
        Ok(self.store().committed_event(event_id).await?)
    }

    pub async fn committed_event_by_commit_id(
        &self,
        commit_id: &RealmCommitId,
    ) -> ServiceResult<Option<soland_storage::CommittedEventRecord>> {
        Ok(self.store().committed_event_by_commit_id(commit_id).await?)
    }

    pub async fn current_mimi_room_binding(
        &self,
        room_uri: &arkret_wire::MimiRoomUri,
    ) -> ServiceResult<Option<soland_storage::MimiRoomBindingCurrentRecord>> {
        Ok(self.store().current_mimi_room_binding(room_uri).await?)
    }

    pub async fn current_agent_result(
        &self,
        realm_id: &arkret_wire::RealmId,
        selector: &arkret_wire::CurrentSelector,
    ) -> ServiceResult<Option<arkret_wire::TypedCurrentResult>> {
        Ok(self
            .store()
            .current_agent_result(realm_id, selector)
            .await?)
    }

    pub async fn realm_state_snapshot_material(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> ServiceResult<Option<soland_storage::RealmStateSnapshotMaterial>> {
        Ok(self.store().realm_state_snapshot_material(realm_id).await?)
    }

    /// Keyset page over one independent commit stream.
    ///
    /// Paging uses a `stream_position` keyset inside one [`CommitStreamRef`].
    /// The direction selects either the forward or backward side of a position;
    /// `truncated` indicates whether another page exists in that direction.
    pub async fn scan_stream(
        &self,
        request: &StreamScanRequest,
    ) -> ServiceResult<StreamScanOutcome> {
        request.validate().map_err(|error| {
            crate::ServiceError::SchemaViolation(format!("invalid stream scan request: {error}"))
        })?;
        let outcome = self.store().scan_stream(request).await?;
        outcome.validate_for_request(request).map_err(|error| {
            crate::ServiceError::SchemaViolation(format!("invalid stream scan outcome: {error}"))
        })?;
        Ok(outcome)
    }

    pub async fn install_handoff(&self, request: &AuthorityHandoffRequest) -> ServiceResult<()> {
        request.validate_shape().map_err(|error| {
            crate::ServiceError::SchemaViolation(format!("invalid authority handoff: {error}"))
        })?;
        self.store()
            .install_handoff(
                &request.handoff,
                &request.final_stream_heads,
                &request.snapshot,
            )
            .await?;
        Ok(())
    }

    pub async fn latest_snapshot(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> ServiceResult<Option<RealmStateSnapshot>> {
        Ok(self.store().latest_snapshot(realm_id).await?)
    }

    pub async fn authority_bundle(
        &self,
        request: &AuthorityBundleRequest,
        local_service_id: &DidCoreId,
        current_route_record: serde_json::Value,
        verification_method: DidUrl,
        signing_key: &SigningKey,
        issued_at: DateTime<Utc>,
    ) -> ServiceResult<RealmAuthorityBundle> {
        request
            .validate()
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        let authority = self
            .store()
            .current_authority(&request.realm_id)
            .await?
            .ok_or_else(|| ServiceError::NotFound("Realm authority is unavailable".to_owned()))?;
        if &authority.service_id != local_service_id {
            return Err(ServiceError::Conflict(
                "this Station is not the current Realm authority".to_owned(),
            ));
        }
        let stream_ref = CommitStreamRef::Realm {
            realm_id: request.realm_id.clone(),
        };
        let scan = self
            .scan_stream(&StreamScanRequest {
                realm_id: request.realm_id.clone(),
                stream_ref: stream_ref.clone(),
                direction: StreamScanDirection::After(None),
                limit: 1,
            })
            .await?;
        let first = scan.committed_events.first().ok_or_else(|| {
            ServiceError::NotFound("Realm genesis Commit is unavailable".to_owned())
        })?;
        let genesis_commit = first.commit().clone();
        let genesis_event = self
            .store()
            .committed_event(&genesis_commit.event_ref)
            .await?
            .ok_or_else(|| ServiceError::Internal("Realm genesis Event is missing".to_owned()))?
            .event;
        let handoffs = self.store().authority_handoffs(&request.realm_id).await?;
        let mut authority_transitions = Vec::with_capacity(handoffs.len());
        for handoff in handoffs {
            let pair = self
                .store()
                .committed_event(&handoff.change_event_ref)
                .await?
                .ok_or_else(|| {
                    ServiceError::Internal("authority change Event is missing".to_owned())
                })?;
            if pair.commit.commit_id != handoff.change_commit_id {
                return Err(ServiceError::Internal(
                    "authority change Commit does not match handoff".to_owned(),
                ));
            }
            authority_transitions.push(RealmAuthorityTransition {
                change_event: pair.event,
                change_commit: pair.commit,
                handoff,
            });
        }
        let realm_stream_head = self
            .store()
            .stream_head(&stream_ref)
            .await?
            .ok_or_else(|| ServiceError::Internal("Realm stream head is missing".to_owned()))?;
        let issued_at = arkret_canonical::normalize_timestamp_canonical(issued_at);
        let expires_at = issued_at + chrono::Duration::seconds(60);
        let assertion_body = RealmAuthorityAssertionUnsignedBody {
            realm_id: &request.realm_id,
            current_generation: authority.generation,
            current_service_id: &authority.service_id,
            last_handoff_ref: &authority.last_handoff_ref,
            realm_stream_head: &realm_stream_head,
            nonce: &request.nonce,
            expires_at,
        };
        let signature = arkret_signatures::detached_object::sign_detached_object(
            &assertion_body,
            DetachedSignatureContext::RealmAuthorityCurrentAssertion,
            verification_method,
            issued_at,
            signing_key,
        )
        .map_err(|error| ServiceError::Internal(error.to_string()))?;
        let bundle = RealmAuthorityBundle {
            realm_id: request.realm_id.clone(),
            genesis_event,
            genesis_commit,
            authority_transitions,
            current_generation: authority.generation,
            current_service_id: authority.service_id.clone(),
            current_route_record,
            realm_stream_head: realm_stream_head.clone(),
            bundle_issued_at: issued_at,
            current_assertion: RealmAuthorityCurrentAssertion {
                realm_id: request.realm_id.clone(),
                current_generation: authority.generation,
                current_service_id: authority.service_id.clone(),
                last_handoff_ref: authority.last_handoff_ref.clone(),
                realm_stream_head,
                nonce: request.nonce.clone(),
                expires_at,
                signature,
            },
        };
        bundle
            .validate_for_request(request, issued_at)
            .map_err(|error| ServiceError::Internal(error.to_string()))?;
        if self.store().current_authority(&request.realm_id).await? != Some(authority)
            || self.store().stream_head(&stream_ref).await?
                != Some(bundle.realm_stream_head.clone())
        {
            return Err(ServiceError::Conflict(
                "Realm authority changed while building the bundle".to_owned(),
            ));
        }
        Ok(bundle)
    }
}

/// HTTP-facing protocol port.
///
/// The concrete Station implementation performs authorization and signing.
/// Self submissions carry the authenticated session through the service
/// boundary so authorization cannot be inferred from the Event body alone.
/// HTTP validates/deserializes current SDK DTOs before delegating.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedPeerContext {
    /// Identity obtained from the verified peer HTTP Message Signature and
    /// its bound source-service-id header, never from the submission body.
    pub source_service_id: DidCoreId,
}

#[async_trait]
pub trait AuthorityProtocolPort: Send + Sync {
    async fn submit_self_event(
        &self,
        session: &crate::identity::SessionIdentityState,
        request: EventAdmissionSubmission,
    ) -> ServiceResult<AuthoritySubmitOutcome>;

    /// An accepted MLS result is forbidden until the MLS state, every Welcome,
    /// and its authority Commit are visible through one transaction.
    async fn submit_self_mls(
        &self,
        session: &crate::identity::SessionIdentityState,
        request: MlsCommitSubmission,
    ) -> ServiceResult<AuthoritySubmitOutcome>;

    async fn submit_self_direct_conversation_founding(
        &self,
        _session: &crate::identity::SessionIdentityState,
        _request: DirectConversationFoundingUnitSubmission,
    ) -> ServiceResult<DirectConversationFoundingAcceptanceOutcome> {
        Err(crate::ServiceError::internal(
            "Direct Conversation founding is not connected to the authority transaction path",
        ))
    }

    async fn submit_self_ordinary_realm_bootstrap(
        &self,
        _session: &crate::identity::SessionIdentityState,
        _request: OrdinaryRealmBootstrapUnitSubmission,
    ) -> ServiceResult<OrdinaryRealmBootstrapAcceptanceOutcome> {
        Err(crate::ServiceError::internal(
            "ordinary Realm bootstrap is not connected to the authority transaction path",
        ))
    }

    async fn submit_self_membership_compensation(
        &self,
        _session: &crate::identity::SessionIdentityState,
        _request: MembershipCompensationUnitSubmission,
    ) -> ServiceResult<MembershipCompensationAcceptanceOutcome> {
        Err(crate::ServiceError::internal(
            "membership compensation is not connected to the authority transaction path",
        ))
    }

    /// Closed self-endpoint dispatcher. It validates both sides at the service
    /// boundary so a handler cannot return the response branch for a different
    /// request or degrade an aggregate into a partial ordinary outcome.
    async fn submit_self(
        &self,
        session: &crate::identity::SessionIdentityState,
        request: SelfAuthoritySubmitRequest,
    ) -> ServiceResult<SelfAuthoritySubmitOutcome> {
        request.validate().map_err(|error| {
            crate::ServiceError::SchemaViolation(format!(
                "invalid self authority submission: {error}"
            ))
        })?;
        let outcome = match request.clone() {
            SelfAuthoritySubmitRequest::Event(value) => {
                SelfAuthoritySubmitOutcome::Ordinary(self.submit_self_event(session, value).await?)
            }
            SelfAuthoritySubmitRequest::MlsCommit(value) => {
                SelfAuthoritySubmitOutcome::Ordinary(self.submit_self_mls(session, value).await?)
            }
            SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(value) => {
                SelfAuthoritySubmitOutcome::OrdinaryRealmBootstrap(
                    self.submit_self_ordinary_realm_bootstrap(session, value)
                        .await?,
                )
            }
            SelfAuthoritySubmitRequest::DirectConversationFounding(value) => {
                SelfAuthoritySubmitOutcome::DirectConversationFounding(
                    self.submit_self_direct_conversation_founding(session, value)
                        .await?,
                )
            }
            SelfAuthoritySubmitRequest::MembershipCompensation(value) => {
                SelfAuthoritySubmitOutcome::MembershipCompensation(
                    self.submit_self_membership_compensation(session, value)
                        .await?,
                )
            }
        };
        outcome.validate_for_request(&request).map_err(|error| {
            crate::ServiceError::Internal(format!(
                "self authority dispatcher produced an invalid outcome: {error}"
            ))
        })?;
        Ok(outcome)
    }

    async fn submit_peer_committed_replication(
        &self,
        _peer: &AuthenticatedPeerContext,
        _request: PeerCommittedReplicationRequest,
    ) -> ServiceResult<PeerCommittedReplicationOutcome> {
        Err(crate::ServiceError::internal(
            "committed replication is not connected to durable replica persistence",
        ))
    }

    async fn submit_peer_direct_conversation_founding(
        &self,
        _peer: &AuthenticatedPeerContext,
        _request: DirectConversationFoundingFederationSubmission,
    ) -> ServiceResult<DirectConversationFoundingAcceptanceOutcome> {
        Err(crate::ServiceError::internal(
            "peer Direct Conversation founding is not connected to atomic materialization",
        ))
    }

    async fn submit_peer_membership_compensation(
        &self,
        _peer: &AuthenticatedPeerContext,
        _request: MembershipCompensationFederationSubmission,
    ) -> ServiceResult<MembershipCompensationAcceptanceOutcome> {
        Err(crate::ServiceError::internal(
            "peer membership compensation is not connected to atomic materialization",
        ))
    }

    /// Dispatch the closed peer carrier. Canonical Station-to-own-Account-
    /// Authority forwarding has been retired; the enum branches remain only
    /// until the shared SDK carrier is cleaned up and always fail closed here.
    async fn submit_peer(
        &self,
        peer: &AuthenticatedPeerContext,
        request: PeerAuthoritySubmitRequest,
    ) -> ServiceResult<PeerAuthoritySubmitOutcome> {
        request.validate().map_err(|error| {
            crate::ServiceError::SchemaViolation(format!(
                "invalid peer authority submission: {error}"
            ))
        })?;
        let outcome = match request.clone() {
            PeerAuthoritySubmitRequest::AuthorityForwardEvent(_)
            | PeerAuthoritySubmitRequest::AuthorityForwardMls(_) => {
                return Err(crate::ServiceError::SchemaViolation(
                    "canonical authority-forward submission is retired; use the product-private Account Authority adapter"
                        .to_owned(),
                ));
            }
            PeerAuthoritySubmitRequest::CommittedReplication(value) => {
                PeerAuthoritySubmitOutcome::CommittedReplication(
                    self.submit_peer_committed_replication(peer, value).await?,
                )
            }
            PeerAuthoritySubmitRequest::RegisteredAtomicUnit(value) => {
                let branch = value.branch;
                let unit = match value.unit {
                    PeerRegisteredAtomicUnit::DirectConversationFounding(unit) => {
                        PeerRegisteredAtomicUnitOutcomeValue::DirectConversationFounding(
                            self.submit_peer_direct_conversation_founding(peer, unit)
                                .await?,
                        )
                    }
                    PeerRegisteredAtomicUnit::MembershipCompensation(unit) => {
                        PeerRegisteredAtomicUnitOutcomeValue::MembershipCompensation(
                            self.submit_peer_membership_compensation(peer, unit).await?,
                        )
                    }
                };
                PeerAuthoritySubmitOutcome::RegisteredAtomicUnit(PeerRegisteredAtomicUnitOutcome {
                    branch,
                    outcome: unit,
                })
            }
        };
        outcome.validate_for_request(&request).map_err(|error| {
            crate::ServiceError::Internal(format!(
                "peer authority dispatcher produced an invalid outcome: {error}"
            ))
        })?;
        Ok(outcome)
    }

    async fn scan_stream(&self, request: StreamScanRequest) -> ServiceResult<StreamScanOutcome>;

    async fn authority_bundle(
        &self,
        request: AuthorityBundleRequest,
    ) -> ServiceResult<RealmAuthorityBundle>;

    async fn install_authority_handoff(
        &self,
        request: AuthorityHandoffRequest,
    ) -> ServiceResult<RealmAuthorityHandoff>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_commit_identity_and_signature_cover_the_closed_body() {
        let genesis_event =
            arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x11; 32]);
        let realm_id = arkret_wire::RealmId::from_event_id(&genesis_event);
        let service_id =
            arkret_wire::DidCoreId::new("ak:did_core:web:station.example".to_owned()).unwrap();
        let event = arkret_wire::test_support::raw_event_at(
            arkret_wire::EventKind::MessageCreate.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            arkret_wire::DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
            service_id.clone(),
            serde_json::json!({"body": "atomic admission"}),
            chrono::DateTime::parse_from_rfc3339("2026-09-20T08:00:00.123Z")
                .unwrap()
                .with_timezone(&Utc),
        )
        .unwrap();
        let authority = CurrentRealmAuthority {
            realm_id,
            generation: 3,
            service_id,
            authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                genesis_event,
            ),
            last_handoff_ref: None,
        };
        let signing_key = SigningKey::from_bytes(&[0x44; 32]);
        let committed_at = chrono::DateTime::parse_from_rfc3339("2026-09-20T08:00:01.456789Z")
            .unwrap()
            .with_timezone(&Utc);
        let commit = build_signed_event_commit(
            &event,
            &authority,
            None,
            DidUrl::new("did:web:station.example#notary-key").unwrap(),
            &signing_key,
            committed_at,
        )
        .unwrap();

        assert_eq!(commit.stream_position, 0);
        assert!(commit.previous_commit_ref.is_none());
        assert_eq!(commit.committed_at.timestamp_subsec_micros(), 456_000);
        let unsigned = arkret_canonical::unsigned_value(&commit, &["signature"]).unwrap();
        assert_eq!(
            commit.signature.signed_digest,
            arkret_signatures::detached_object::detached_object_signed_digest(&unsigned).unwrap(),
            "the signature must seal the exact wire Commit minus signature"
        );
        let replay = build_signed_event_commit(
            &event,
            &authority,
            None,
            DidUrl::new("did:web:station.example#notary-key").unwrap(),
            &signing_key,
            committed_at,
        )
        .unwrap();
        assert_eq!(commit, replay, "same closed input must produce one Commit");
    }

    #[test]
    fn signed_snapshot_identity_and_signature_cover_the_closed_body() {
        let genesis_event =
            arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x21; 32]);
        let realm_id = arkret_wire::RealmId::from_event_id(&genesis_event);
        let stream_ref = arkret_wire::CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        };
        let material = soland_storage::RealmStateSnapshotMaterial {
            realm_id: realm_id.clone(),
            governance_generation: 4,
            visible_stream_heads: vec![arkret_wire::CommitStreamHead {
                stream_ref: stream_ref.clone(),
                stream_position: 7,
                commit_id: arkret_wire::RealmCommitId::from_digest([0x22; 32]),
            }],
            current_state_entries: vec![arkret_wire::TypedCurrentResult::Value {
                selector: arkret_wire::CurrentSelector::RealmPolicy,
                revision: arkret_wire::CurrentRevision {
                    commit_id: arkret_wire::RealmCommitId::from_digest([0x22; 32]),
                    stream_position: 7,
                },
                value: serde_json::json!({"policy": "closed"}),
            }],
            retention_and_history_floor: arkret_wire::RetentionAndHistoryFloor {
                history_access: arkret_wire::HistoryAccess::AllHistoryForCurrentMembers,
                stream_floors: vec![arkret_wire::StreamHistoryFloor {
                    stream_ref,
                    oldest_position: 2,
                }],
            },
        };
        let signing_key = SigningKey::from_bytes(&[0x45; 32]);
        let created_at = chrono::DateTime::parse_from_rfc3339("2026-09-22T08:00:01.456789Z")
            .unwrap()
            .with_timezone(&Utc);
        let snapshot = build_signed_realm_state_snapshot(
            &material,
            DidUrl::new("did:web:station.example#notary-key").unwrap(),
            &signing_key,
            created_at,
        )
        .unwrap();

        assert_eq!(snapshot.created_at.timestamp_subsec_micros(), 456_000);
        let identity = RealmSnapshotIdentityBody {
            realm_id: &snapshot.realm_id,
            governance_generation: snapshot.governance_generation,
            visible_stream_heads: &snapshot.visible_stream_heads,
            current_state_entries: &snapshot.current_state_entries,
            retention_and_history_floor: &snapshot.retention_and_history_floor,
            created_at: snapshot.created_at,
        };
        let expected_id =
            arkret_wire::RealmSnapshotId::from_digest(arkret_canonical::sha256_bytes(
                &arkret_canonical::canonical_json_bytes(&identity).unwrap(),
            ));
        assert_eq!(snapshot.snapshot_id, expected_id);
        let unsigned = arkret_canonical::unsigned_value(&snapshot, &["signature"]).unwrap();
        assert_eq!(
            snapshot.signature.signed_digest,
            arkret_signatures::detached_object::detached_object_signed_digest(&unsigned).unwrap(),
            "the signature must seal the exact wire Snapshot minus signature"
        );
    }
}
