use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use arkret_identifiers::{BlobRef, DidCoreId, DidFullId, EventId, Hash};
use arkret_models_collaboration::agent_operations::AgentLifecycleState;
use arkret_models_collaboration::contact_operations::{
    ContactRoundEvidenceBundle, PeerContactMirrorReceipt, PeerContactSubmitOutcome,
    RequestAcceptanceReceipt,
};
use arkret_models_collaboration::governance::agent_artifacts::PublicKey;
use arkret_models_collaboration::objects::account_status::AccountStatus;
use arkret_models_crypto::{
    DeviceGenerationStatus, RecoveryIdentityModel, RecoveryPublicationAuthorityContext,
};
use arkret_models_identity::service_identity::{
    ServiceRegistrationKey, ServiceRegistrationOutcome,
};
use arkret_wire::{
    DeviceReanchorPreFenceSealFrontier, DidUrl, LeaseBasisRef, NonEmptyString, NotaryJoseAlgorithm,
    NotaryKeyKind, NotarySignerDescriptor, OpaqueLocalId,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ed25519_dalek::Signer as _;
use parking_lot::Mutex;
use serde_json::Value;

/// Freeze one locally held Ed25519 notary key into the canonical Realm
/// notary descriptor. Callers must pass the verification key belonging to the
/// exact signer that will issue Seals; this helper never resolves or invents
/// key material.
pub fn ed25519_notary_signer_descriptor(
    actor_id: DidCoreId,
    verification_method: DidUrl,
    public_key: &[u8; 32],
) -> Result<NotarySignerDescriptor, String> {
    let descriptor = NotarySignerDescriptor {
        actor_id,
        verification_method,
        key_kind: NotaryKeyKind::Ed25519Raw32,
        jose_algorithm: NotaryJoseAlgorithm::Ed25519,
        frozen_public_key_b64u: arkret_canonical::base64url_encode(public_key),
        frozen_public_key_digest: Hash::new(arkret_canonical::sha256_digest(public_key))
            .map_err(|error| error.to_string())?,
    };
    descriptor.validate().map_err(|error| error.to_string())?;
    Ok(descriptor)
}

/// Sign a frozen-notary transcript with the SDK-owned detached-JWS `kid`
/// binding required by [`arkret_wire::SealSignature`].
pub fn sign_ed25519_frozen_notary_jws(
    canonical_bytes: &[u8],
    verification_method: &DidUrl,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<String, String> {
    let signing_input = arkret_signatures::proof::ed25519_detached_jws_signing_input(
        canonical_bytes,
        Some(verification_method.as_str()),
    )
    .map_err(|error| error.to_string())?;
    let signature = signing_key.sign(signing_input.as_bytes());
    arkret_signatures::proof::ed25519_detached_jws_from_signature(
        &signature.to_bytes(),
        Some(verification_method.as_str()),
    )
    .map_err(|error| error.to_string())
}

/// SDK [`arkret_wire::PayloadSigner`] adapter for frozen Realm-notary Seals.
pub struct FrozenEd25519NotarySigner {
    signing_key: ed25519_dalek::SigningKey,
    signer_did: DidFullId,
    verification_method: DidUrl,
}

impl FrozenEd25519NotarySigner {
    #[must_use]
    pub fn from_seed(seed: [u8; 32], signer_did: DidFullId, verification_method: DidUrl) -> Self {
        Self {
            signing_key: ed25519_dalek::SigningKey::from_bytes(&seed),
            signer_did,
            verification_method,
        }
    }

    #[must_use]
    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.signing_key.verifying_key()
    }
}

impl arkret_wire::PayloadSigner for FrozenEd25519NotarySigner {
    fn signer_did(&self) -> &DidFullId {
        &self.signer_did
    }

    fn verification_method_id(&self) -> &DidUrl {
        &self.verification_method
    }

    fn sign_payload(
        &self,
        canonical_bytes: &[u8],
    ) -> arkret_wire::Result<arkret_wire::PayloadSignature> {
        let payload_digest = Hash::new(arkret_canonical::sha256_digest(canonical_bytes))?;
        let jws = sign_ed25519_frozen_notary_jws(
            canonical_bytes,
            &self.verification_method,
            &self.signing_key,
        )
        .map_err(arkret_wire::Error::Protocol)?;
        Ok(arkret_wire::PayloadSignature {
            verification_method: self.verification_method.clone(),
            payload_digest,
            created_at: Utc::now(),
            jws,
            extra: BTreeMap::new(),
        })
    }
}

/// A consent cell is addressed by its subject: `consent_id` is the cell
/// subject of exactly one holder (`consent-model.md` section 3.1), so the
/// runtime key is `(holder, cell_id)`. `(peer, consent_scope)` is the intent
/// carried by the cell's dots, not part of its address.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConsentCellKey {
    pub holder: String,
    pub cell_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsentGrantDot {
    pub dot: String,
    pub not_before: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub granted_at: DateTime<Utc>,
}

/// One holder-private `ak.component.consent.grant.v1` or_set cell.
///
/// `peer` and `consent_scope` are the intent frozen by the cell's first
/// accepted grant; every later dot on the same `consent_id` MUST carry that
/// same intent (`consent-model.md` sections 3.1 and 3.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsentCellRecord {
    pub cell_id: String,
    pub holder: String,
    pub peer: String,
    pub consent_scope: String,
    pub grant_dots: BTreeMap<String, ConsentGrantDot>,
    pub revoked_dots: BTreeSet<String>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MimiConsentCorrelation {
    pub consent_id: String,
    pub requester_id: String,
    pub target_kind: String,
    pub target_id: String,
    pub purpose: String,
    pub strand_id: Option<String>,
    pub source_service_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug)]
pub struct ContactRecord {
    pub requester: String,
    pub target: String,
    pub contact_round_id: Option<String>,
    pub version: Option<u64>,
    pub granted_to_target_scopes: Vec<String>,
    pub granted_to_requester_scopes: Vec<String>,
    pub status: String,
    pub request_event_ref: Option<String>,
    pub request_receipts: Vec<RequestAcceptanceReceipt>,
    pub request_mirror_receipts: Vec<PeerContactMirrorReceipt>,
    pub contact_round_evidence: Option<ContactRoundEvidenceBundle>,
    /// Immediate terminal predecessor first, followed by its predecessors up
    /// to the unique root round. Keeping the verified bundles beside the
    /// current row lets the resolver supply the exact re-contact continuity
    /// chain without reconstructing signed evidence from Event references.
    pub contact_round_evidence_history: Vec<ContactRoundEvidenceBundle>,
    pub control_outcomes: Vec<PeerContactSubmitOutcome>,
    pub response_event_ref: Option<String>,
    pub tombstone_event_ref: Option<String>,
    pub message: Option<String>,
    pub peer_service_id: Option<String>,
    pub peer_service_resolution: Option<Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// The coordinates one `ak.direct_conversation.bound` endorsement settles.
///
/// `contact-and-direct-conversation.md` §8.3: the binding is written once and
/// never retired, so this carries no lifecycle state, no `supersedes` ref and
/// no separately mutable `mls_group_id`; the MLS group is uniquely derived
/// from the immutable Realm scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectConversationBindingRecord {
    pub participants_unordered: Vec<String>,
    pub realm_id: String,
    pub main_strand_id: String,
    pub created_at: DateTime<Utc>,
    /// One Event that endorsed these coordinates. The or_set can hold an
    /// endorsement per participant; this is the lowest endorsing `actor_id`'s,
    /// so every replica names the same one. It is evidence, not a head — the
    /// binding has no successor to point at.
    pub binding_event_ref: String,
}

/// One or_set element of `ak.component.direct_conversation.binding.v1`.
///
/// The element key is `(binding_digest, envelope.actor_id)` (§8.3): the same
/// participant re-signing the same coordinates counts once, and both
/// participants signing the same coordinates are compatible adds.
#[derive(Clone, Debug)]
pub struct DirectConversationEndorsement {
    pub actor_id: String,
    pub binding_event_ref: String,
}

/// The or_set cell resolved for one `pair_key`.
///
/// More than one distinct endorsement digest is
/// `direct_conversation_pair_materialization_conflict` (§5.7 / §8.3): the pair
/// freezes and no side is picked as canonical.
#[derive(Clone, Debug, Default)]
pub struct DirectConversationBindings {
    entries: BTreeMap<
        String,
        (
            DirectConversationCoordinatesRecord,
            BTreeMap<String, String>,
        ),
    >,
}

/// The coordinates half of a binding, before an endorsing Event is named.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectConversationCoordinatesRecord {
    pub participants_unordered: Vec<String>,
    pub realm_id: String,
    pub main_strand_id: String,
    pub created_at: DateTime<Utc>,
}

impl DirectConversationBindings {
    /// or_set add. `digest` identifies the endorsed coordinates; re-adding the
    /// same `(digest, actor_id)` is idempotent, never a conflict.
    pub fn endorse(
        &mut self,
        digest: String,
        coordinates: DirectConversationCoordinatesRecord,
        endorsement: DirectConversationEndorsement,
    ) {
        let entry = self
            .entries
            .entry(digest)
            .or_insert_with(|| (coordinates, BTreeMap::new()));
        entry
            .1
            .insert(endorsement.actor_id, endorsement.binding_event_ref);
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// `true` once two distinct digests coexist for the same pair.
    pub fn is_conflicted(&self) -> bool {
        self.entries.len() > 1
    }

    /// The settled coordinates, or `None` while the pair carries no
    /// endorsement or carries conflicting ones.
    pub fn settled(&self) -> Option<DirectConversationBindingRecord> {
        (self.entries.len() == 1)
            .then(|| self.entries.values().next())
            .flatten()
            .and_then(Self::resolve)
    }

    /// Coordinates to report alongside a conflict diagnosis. Any endorsed set
    /// works: the resolver only needs a pair of coordinates to name, and §5.7
    /// forbids treating either one as the winner.
    pub fn any_endorsed(&self) -> Option<DirectConversationBindingRecord> {
        self.entries.values().next().and_then(Self::resolve)
    }

    fn resolve(
        entry: &(
            DirectConversationCoordinatesRecord,
            BTreeMap<String, String>,
        ),
    ) -> Option<DirectConversationBindingRecord> {
        let (coordinates, endorsers) = entry;
        // `BTreeMap` order makes the named endorsement the lowest actor id's,
        // so two replicas holding the same or_set report the same Event.
        let binding_event_ref = endorsers.values().next()?.clone();
        Some(DirectConversationBindingRecord {
            participants_unordered: coordinates.participants_unordered.clone(),
            realm_id: coordinates.realm_id.clone(),
            main_strand_id: coordinates.main_strand_id.clone(),
            created_at: coordinates.created_at,
            binding_event_ref,
        })
    }

    /// Every distinct endorsement digest carried for this pair.
    pub fn digests(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }

    pub fn endorsers(&self) -> impl Iterator<Item = &str> {
        self.entries
            .values()
            .flat_map(|(_, endorsers)| endorsers.keys().map(String::as_str))
    }
}

use crate::ServiceResult;

fn lifecycle_status_from_wire(value: &str) -> AccountStatus {
    match value {
        "erased" => AccountStatus::ErasurePending,
        _ => AccountStatus::from_wire(value).unwrap_or_else(|| {
            tracing::warn!(state = value, "unknown account lifecycle state");
            AccountStatus::Suspended
        }),
    }
}

#[derive(Clone, Debug)]
pub struct FindAccountByActorQuery {
    pub actor_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountIdentity {
    pub account_id: String,
}

#[derive(Clone, Debug)]
pub struct AccountProfileState {
    pub id: String,
    pub did: String,
    pub localpart: String,
    pub display_name: Option<String>,
    pub bio: Option<String>,
    pub avatar_blob_ref: Option<BlobRef>,
    pub created_at: DateTime<Utc>,
}

impl AccountProfileState {
    pub fn handle(&self) -> String {
        if self.localpart.is_empty() {
            String::new()
        } else {
            format!("@{}", self.localpart)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountLocalpartState {
    pub id: String,
    pub account_did: String,
    pub localpart: String,
    pub is_primary: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct AccountLifecycleState {
    pub state: String,
    pub reason: Option<String>,
    pub changed_by: Option<String>,
    pub changed_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct RegisterAccountCommand {
    pub account_id: String,
    pub actor_id: String,
    pub localpart: String,
    pub display_name: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct AccountDataState {
    pub actor_id: String,
    pub account_data_key: String,
    pub revision: u64,
    pub payload: Value,
    pub tombstone: bool,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub enum AccountDataCasOutcome {
    Applied(AccountDataState),
    Conflict(Option<AccountDataState>),
}

#[async_trait]
pub trait AccountDataPort: Send + Sync {
    async fn entry(
        &self,
        actor_id: &str,
        account_data_key: &str,
    ) -> ServiceResult<Option<AccountDataState>>;
    async fn entries_for_actor(&self, actor_id: &str) -> ServiceResult<Vec<AccountDataState>>;
    async fn compare_and_set(
        &self,
        entry: AccountDataState,
        expected_revision: u64,
    ) -> ServiceResult<AccountDataCasOutcome>;
}

#[derive(Clone)]
pub struct AccountDataService {
    account_data: Arc<dyn AccountDataPort>,
}

/// Read side of the durable holder-private consent projection.
///
/// Consent cells are only ever written inside the Event commit unit of work
/// that accepts their `ak.consent.grant` / `ak.consent.revoke` Control Move,
/// so this port carries no writer: a second write path would be a second
/// source of truth for replicated cell state.
#[async_trait]
pub trait ConsentCellPort: Send + Sync {
    async fn cells(&self) -> ServiceResult<Vec<(ConsentCellKey, ConsentCellRecord)>>;
}

#[async_trait]
pub trait MimiConsentCorrelationPort: Send + Sync {
    async fn save_correlation(&self, correlation: MimiConsentCorrelation) -> ServiceResult<()>;
    async fn correlation(&self, consent_id: &str) -> ServiceResult<Option<MimiConsentCorrelation>>;
}

#[derive(Clone)]
pub struct ConsentService {
    consent_cells: Arc<dyn ConsentCellPort>,
    mimi_correlations: Arc<dyn MimiConsentCorrelationPort>,
    runtime_cells: Arc<Mutex<BTreeMap<ConsentCellKey, ConsentCellRecord>>>,
}

#[async_trait]
pub trait ContactPort: Send + Sync {
    async fn contact_any(
        &self,
        requester: &str,
        target: &str,
    ) -> ServiceResult<Option<ContactRecord>>;
    async fn contacts_for_actor(&self, actor_id: &str) -> ServiceResult<Vec<ContactRecord>>;
    async fn save_contact(&self, contact: ContactRecord) -> ServiceResult<()>;
    async fn save_contact_if_updated_at(
        &self,
        expected_updated_at: DateTime<Utc>,
        contact: ContactRecord,
    ) -> ServiceResult<bool>;
}

#[async_trait]
pub trait InviteReceivePolicyPort: Send + Sync {
    async fn save_policy(
        &self,
        policy: arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
    ) -> ServiceResult<()>;
    async fn policies(
        &self,
    ) -> ServiceResult<
        Vec<(
            String,
            arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
        )>,
    >;
}

#[derive(Clone)]
pub struct ContactService {
    contacts: Arc<dyn ContactPort>,
    invite_policies: Arc<dyn InviteReceivePolicyPort>,
    runtime_invite_policies: Arc<
        Mutex<
            BTreeMap<
                String,
                arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
            >,
        >,
    >,
    /// Resolved `ak.component.direct_conversation.binding.v1` or_set per
    /// `pair_key`. There is no durable mirror: the cell is control-plane and
    /// sealed, so hydration rebuilds it by replaying the accepted
    /// `ak.direct_conversation.bound` Events, which are the authority.
    runtime_direct_bindings: Arc<Mutex<BTreeMap<String, DirectConversationBindings>>>,
}

impl ContactService {
    pub async fn hydrate_runtime(&self) -> ServiceResult<()> {
        self.replace_runtime_invite_policies(self.invite_policies.policies().await?);
        Ok(())
    }

    pub fn new(
        contacts: Arc<dyn ContactPort>,
        invite_policies: Arc<dyn InviteReceivePolicyPort>,
    ) -> Self {
        Self {
            contacts,
            invite_policies,
            runtime_invite_policies: Arc::new(Mutex::new(BTreeMap::new())),
            runtime_direct_bindings: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub async fn contact_any(
        &self,
        requester: &str,
        target: &str,
    ) -> ServiceResult<Option<ContactRecord>> {
        self.contacts.contact_any(requester, target).await
    }

    pub async fn contacts_for_actor(&self, actor_id: &str) -> ServiceResult<Vec<ContactRecord>> {
        self.contacts.contacts_for_actor(actor_id).await
    }

    pub async fn save_contact(&self, contact: ContactRecord) -> ServiceResult<()> {
        self.contacts.save_contact(contact).await
    }

    pub async fn save_contact_if_updated_at(
        &self,
        expected_updated_at: DateTime<Utc>,
        contact: ContactRecord,
    ) -> ServiceResult<bool> {
        self.contacts
            .save_contact_if_updated_at(expected_updated_at, contact)
            .await
    }

    pub async fn save_invite_policy(
        &self,
        policy: arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
    ) -> ServiceResult<()> {
        self.invite_policies.save_policy(policy.clone()).await?;
        self.runtime_invite_policies
            .lock()
            .insert(policy.subject_id.to_string(), policy);
        Ok(())
    }

    pub fn replace_runtime_invite_policies(
        &self,
        policies: impl IntoIterator<
            Item = (
                String,
                arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
            ),
        >,
    ) {
        *self.runtime_invite_policies.lock() = policies.into_iter().collect();
    }

    pub fn invite_policy(
        &self,
        subject_id: &str,
    ) -> Option<arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy>
    {
        self.runtime_invite_policies.lock().get(subject_id).cloned()
    }

    /// or_set add for one accepted `ak.direct_conversation.bound` Event.
    ///
    /// `digest` is the endorsement identity — the canonical bytes of the
    /// payload with `created_at` excluded, so the same coordinates endorsed by
    /// both participants (or re-signed by one) collapse to one element per
    /// actor. Adds never conflict; a second, different digest is what
    /// `is_conflicted` then reports (§8.3).
    pub fn endorse_direct_binding(
        &self,
        pair_key: &str,
        digest: String,
        coordinates: DirectConversationCoordinatesRecord,
        endorsement: DirectConversationEndorsement,
    ) {
        self.runtime_direct_bindings
            .lock()
            .entry(pair_key.to_owned())
            .or_default()
            .endorse(digest, coordinates, endorsement);
    }

    pub fn runtime_direct_binding_count(&self) -> usize {
        self.runtime_direct_bindings.lock().len()
    }

    /// The full resolved or_set for one pair.
    pub fn direct_bindings_for_pair(&self, pair_key: &str) -> Option<DirectConversationBindings> {
        self.runtime_direct_bindings.lock().get(pair_key).cloned()
    }

    /// The settled coordinates for one pair: `Some` only when every
    /// endorsement agrees on the same digest.
    pub fn direct_binding(&self, pair_key: &str) -> Option<DirectConversationBindingRecord> {
        self.runtime_direct_bindings
            .lock()
            .get(pair_key)
            .and_then(DirectConversationBindings::settled)
    }

    /// `true` when this pair carries two distinct endorsement digests
    /// (`direct_conversation_pair_materialization_conflict`).
    pub fn direct_binding_is_conflicted(&self, pair_key: &str) -> bool {
        self.runtime_direct_bindings
            .lock()
            .get(pair_key)
            .is_some_and(DirectConversationBindings::is_conflicted)
    }

    pub fn settled_direct_binding_for_realm(
        &self,
        realm_id: &str,
    ) -> Option<DirectConversationBindingRecord> {
        self.runtime_direct_bindings
            .lock()
            .values()
            .find_map(|bindings| {
                bindings
                    .settled()
                    .filter(|record| record.realm_id == realm_id)
            })
    }

    /// Test/bootstrap seam: install a single-endorsement or_set directly.
    pub fn install_direct_binding(
        &self,
        pair_key: impl Into<String>,
        digest: impl Into<String>,
        coordinates: DirectConversationCoordinatesRecord,
        endorsement: DirectConversationEndorsement,
    ) {
        self.runtime_direct_bindings
            .lock()
            .entry(pair_key.into())
            .or_default()
            .endorse(digest.into(), coordinates, endorsement);
    }

    /// Fixture-only: drop every runtime direct binding installed through
    /// [`Self::install_direct_binding`]. No production path resets the map, so
    /// this stays out of release builds.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn clear_runtime_direct_bindings(&self) {
        self.runtime_direct_bindings.lock().clear();
    }
}

impl ConsentService {
    pub fn new(
        consent_cells: Arc<dyn ConsentCellPort>,
        mimi_correlations: Arc<dyn MimiConsentCorrelationPort>,
    ) -> Self {
        Self {
            consent_cells,
            mimi_correlations,
            runtime_cells: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub async fn save_mimi_correlation(
        &self,
        correlation: MimiConsentCorrelation,
    ) -> ServiceResult<()> {
        self.mimi_correlations.save_correlation(correlation).await
    }

    pub async fn mimi_correlation(
        &self,
        consent_id: &str,
    ) -> ServiceResult<Option<MimiConsentCorrelation>> {
        self.mimi_correlations.correlation(consent_id).await
    }

    pub async fn hydrate_runtime(&self) -> ServiceResult<()> {
        self.replace_runtime_cells(self.consent_cells.cells().await?);
        Ok(())
    }

    pub fn replace_runtime_cells(
        &self,
        cells: impl IntoIterator<Item = (ConsentCellKey, ConsentCellRecord)>,
    ) {
        *self.runtime_cells.lock() = cells.into_iter().collect();
    }

    /// Publish one durably committed consent cell into the runtime
    /// projection. The Event commit already succeeded, so this only refreshes
    /// the working view a restart would rebuild from `hydrate_runtime`.
    pub fn install_committed_cell(&self, cell: ConsentCellRecord) {
        let key = consent_cell_key(&cell.holder, &cell.cell_id);
        self.runtime_cells.lock().insert(key, cell);
    }

    /// Every consent cell the holder owns. Consent is holder-private
    /// (`consent-model.md` section 8): a peer never reads cells, dots or
    /// expiry, so there is no peer-visible listing.
    pub fn holder_cells(&self, holder: &str) -> Vec<ConsentCellRecord> {
        self.runtime_cells
            .lock()
            .values()
            .filter(|cell| cell.holder == holder)
            .cloned()
            .collect()
    }

    pub fn holder_cell(&self, holder: &str, cell_id: &str) -> Option<ConsentCellRecord> {
        self.runtime_cells
            .lock()
            .get(&consent_cell_key(holder, cell_id))
            .cloned()
    }

    pub fn cells_for_pair(&self, holder: &str, peer: &str) -> Vec<ConsentCellRecord> {
        self.runtime_cells
            .lock()
            .values()
            .filter(|cell| cell.holder == holder && cell.peer == peer)
            .cloned()
            .collect()
    }

    /// Holder cells whose frozen intent is exactly `(peer, consent_scope)`.
    pub fn cells_for_intent(
        &self,
        holder: &str,
        peer: &str,
        consent_scope: &str,
    ) -> Vec<ConsentCellRecord> {
        self.runtime_cells
            .lock()
            .values()
            .filter(|cell| {
                cell.holder == holder && cell.peer == peer && cell.consent_scope == consent_scope
            })
            .cloned()
            .collect()
    }
}

fn consent_cell_key(holder: &str, cell_id: &str) -> ConsentCellKey {
    ConsentCellKey {
        holder: holder.to_owned(),
        cell_id: cell_id.to_owned(),
    }
}

impl AccountDataService {
    pub fn new(account_data: Arc<dyn AccountDataPort>) -> Self {
        Self { account_data }
    }

    pub async fn entry(
        &self,
        actor_id: &str,
        account_data_key: &str,
    ) -> ServiceResult<Option<AccountDataState>> {
        self.account_data.entry(actor_id, account_data_key).await
    }

    pub async fn entries_for_actor(&self, actor_id: &str) -> ServiceResult<Vec<AccountDataState>> {
        self.account_data.entries_for_actor(actor_id).await
    }

    pub async fn compare_and_set(
        &self,
        entry: AccountDataState,
        expected_revision: u64,
    ) -> ServiceResult<AccountDataCasOutcome> {
        self.account_data
            .compare_and_set(entry, expected_revision)
            .await
    }
}

#[derive(Clone, Debug, Default)]
pub struct ListActiveDeviceActorsQuery;

#[derive(Clone, Debug)]
pub struct FindDeviceQuery {
    pub actor_id: String,
    pub device_id: String,
}

#[derive(Clone, Debug)]
pub struct DeviceIdentity {
    pub actor_id: String,
    pub device_id: String,
    pub display_name: Option<String>,
    pub verification_state: String,
    pub payload: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[async_trait]
pub trait DeviceKeyPort: Send + Sync {
    async fn save_bundle(
        &self,
        actor_id: String,
        device_id: String,
        payload: Value,
    ) -> ServiceResult<()>;
    async fn bundle(&self, actor_id: &str, device_id: &str) -> ServiceResult<Option<Value>>;
}

#[async_trait]
pub trait OneTimeKeyPort: Send + Sync {
    async fn save_keys(
        &self,
        actor_id: String,
        device_id: String,
        keys: Vec<Value>,
    ) -> ServiceResult<()>;
    async fn claim_key(&self, actor_id: &str, device_id: &str) -> ServiceResult<Option<Value>>;
}

#[derive(Clone)]
pub struct KeyMaterialService {
    device_keys: Arc<dyn DeviceKeyPort>,
    one_time_keys: Arc<dyn OneTimeKeyPort>,
}

impl KeyMaterialService {
    pub fn new(
        device_keys: Arc<dyn DeviceKeyPort>,
        one_time_keys: Arc<dyn OneTimeKeyPort>,
    ) -> Self {
        Self {
            device_keys,
            one_time_keys,
        }
    }

    pub async fn save_bundle(
        &self,
        actor_id: String,
        device_id: String,
        payload: Value,
    ) -> ServiceResult<()> {
        self.device_keys
            .save_bundle(actor_id, device_id, payload)
            .await
    }

    pub async fn bundle(&self, actor_id: &str, device_id: &str) -> ServiceResult<Option<Value>> {
        self.device_keys.bundle(actor_id, device_id).await
    }

    pub async fn save_one_time_keys(
        &self,
        actor_id: String,
        device_id: String,
        keys: Vec<Value>,
    ) -> ServiceResult<()> {
        self.one_time_keys
            .save_keys(actor_id, device_id, keys)
            .await
    }

    pub async fn claim_one_time_key(
        &self,
        actor_id: &str,
        device_id: &str,
    ) -> ServiceResult<Option<Value>> {
        self.one_time_keys.claim_key(actor_id, device_id).await
    }
}

#[derive(Clone, Debug)]
pub struct SaveDeviceCommand {
    pub actor_id: String,
    pub device_id: String,
    pub display_name: Option<String>,
    pub device: DeviceIdentity,
}

#[derive(Clone, Debug)]
pub struct FindAgentControllerQuery {
    pub agent_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentController {
    pub controller_id: String,
}

#[async_trait]
pub trait AccountLookupPort: Send + Sync {
    async fn find_account_by_actor(&self, actor_id: &str)
    -> ServiceResult<Option<AccountIdentity>>;
    async fn register_account(&self, command: RegisterAccountCommand) -> ServiceResult<()>;
    async fn account(&self, actor_id: &str) -> ServiceResult<Option<AccountProfileState>>;
    async fn accounts(&self) -> ServiceResult<Vec<AccountProfileState>>;
    async fn save_account(&self, account: AccountProfileState) -> ServiceResult<()>;
    async fn delete_account(&self, actor_id: &str) -> ServiceResult<()>;
    async fn account_localparts(&self, actor_id: &str)
    -> ServiceResult<Vec<AccountLocalpartState>>;
    async fn localpart_owner(
        &self,
        localpart: &str,
    ) -> ServiceResult<Option<AccountLocalpartState>>;
    async fn add_localpart(
        &self,
        actor_id: &str,
        localpart: &str,
        primary: bool,
    ) -> ServiceResult<AccountLocalpartState>;
    async fn set_primary_localpart(
        &self,
        actor_id: &str,
        localpart: &str,
    ) -> ServiceResult<AccountLocalpartState>;
    async fn remove_localpart(&self, actor_id: &str, localpart: &str) -> ServiceResult<()>;
    async fn clear_localparts(&self, actor_id: &str) -> ServiceResult<()>;
    async fn record_handle_release(
        &self,
        localpart: &str,
        released_at: DateTime<Utc>,
    ) -> ServiceResult<()>;
    async fn save_account_lifecycle(
        &self,
        actor_id: &str,
        lifecycle: AccountLifecycleState,
    ) -> ServiceResult<()>;
    async fn delete_account_lifecycle(&self, actor_id: &str) -> ServiceResult<()>;
    async fn account_lifecycles(&self) -> ServiceResult<Vec<(String, AccountLifecycleState)>> {
        Ok(Vec::new())
    }
}

#[async_trait]
pub trait DeviceDirectoryPort: Send + Sync {
    async fn list_active_device_actors(&self) -> ServiceResult<Vec<String>>;
    async fn devices(&self) -> ServiceResult<Vec<DeviceIdentity>>;
    async fn find_device(
        &self,
        actor_id: &str,
        device_id: &str,
    ) -> ServiceResult<Option<DeviceIdentity>>;
    async fn save_device(&self, command: SaveDeviceCommand) -> ServiceResult<()>;
    async fn save_device_if_absent(&self, device: DeviceIdentity) -> ServiceResult<bool>;
    async fn devices_for_actor(&self, actor_id: &str) -> ServiceResult<Vec<DeviceIdentity>>;
}

#[async_trait]
pub trait AgentDirectoryPort: Send + Sync {
    async fn find_agent_controller(&self, agent_id: &str)
    -> ServiceResult<Option<AgentController>>;
}

#[derive(Clone)]
pub struct IdentityService {
    accounts: Arc<dyn AccountLookupPort>,
    devices: Arc<dyn DeviceDirectoryPort>,
    agents: Arc<dyn AgentDirectoryPort>,
    account_registration_attempts: AccountRegistrationAttempts,
    account_lifecycles: Arc<Mutex<BTreeMap<String, AccountLifecycleState>>>,
}

type AccountRegistrationAttempts = Arc<Mutex<BTreeMap<String, (DateTime<Utc>, u32)>>>;

#[derive(Clone, Debug)]
pub struct ActivateAgentRuntimeCommand {
    pub agent_id: String,
    pub approval_request_id: OpaqueLocalId,
    pub runtime_key_binding_digest: String,
    pub pairing_request_id: OpaqueLocalId,
    pub paired_request_digest: String,
    pub authorized_event_ref: String,
    pub authorized_verification_method: String,
    pub authorized_public_key_digest: String,
    pub authorized_signing_key_binding:
        arkret_models_identity::agent_signer_evidence::AgentSigningKeyBinding,
    pub authorized_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct RecordAgentPairingCommitIntentCommand {
    pub agent_id: String,
    pub approval_request_id: OpaqueLocalId,
    pub runtime_key_binding_digest: String,
    pub pairing_request_id: OpaqueLocalId,
    pub request_digest: String,
    pub authorize_event_id: String,
    pub signing_key_binding: arkret_models_identity::agent_signer_evidence::AgentSigningKeyBinding,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AgentPairingCommitIntentState {
    pub request_digest: String,
    pub authorize_event_id: String,
    pub signing_key_binding:
        Option<arkret_models_identity::agent_signer_evidence::AgentSigningKeyBinding>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AgentPairingState {
    pub id: String,
    pub controller_id: String,
    pub principal_control_realm_id: String,
    pub controller_authorization_ref: DidUrl,
    pub display_name: Option<String>,
    pub agent_slug: Option<String>,
    pub avatar_blob_ref: Option<String>,
    pub state: AgentLifecycleState,
    pub requested_scope: Option<Value>,
    pub accountability: Option<Value>,
    pub provision_event_refs: Option<Value>,
    pub pairing_request_id: Option<OpaqueLocalId>,
    pub paired_pairing_request_id: Option<OpaqueLocalId>,
    pub paired_request_digest: Option<String>,
    pub pending_pairing_commit_intent: Option<AgentPairingCommitIntentState>,
    pub pairing_code: Option<String>,
    pub pairing_expires_at: Option<DateTime<Utc>>,
    pub approval_request_id: Option<OpaqueLocalId>,
    pub controller_account_id: Option<uuid::Uuid>,
    pub recipient_service_id: Option<String>,
    pub runtime_key_binding_digest: Option<String>,
    pub runtime_public_key_digest: Option<String>,
    pub runtime_attestation_digest: Option<String>,
    pub approval_notification_id: Option<uuid::Uuid>,
    pub runtime_key_request: Option<
        arkret_models_collaboration::agent_operations::AgentRuntimeApprovalControllerProjection,
    >,
    pub approval_requested_at: Option<DateTime<Utc>>,
    pub authorized_event_ref: Option<String>,
    pub authorized_verification_method: Option<String>,
    pub authorized_public_key_digest: Option<String>,
    pub authorized_signing_key_binding:
        Option<arkret_models_identity::agent_signer_evidence::AgentSigningKeyBinding>,
    pub state_changed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct OpenAgentPairingHandle {
    pub pairing_request_id: OpaqueLocalId,
    pub pairing_code: String,
    pub expires_at: DateTime<Utc>,
    pub pending_runtime_key_request: Option<
        arkret_models_collaboration::agent_operations::AgentRuntimeApprovalControllerProjection,
    >,
}

impl OpenAgentPairingHandle {
    pub fn is_live_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at > now
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActiveAgentRuntimeBinding {
    pub completed_pairing_request_id: OpaqueLocalId,
    pub authorized_event_ref: EventId,
    pub verification_method: DidUrl,
    pub public_key_digest: Hash,
    pub signing_key_binding: arkret_models_identity::agent_signer_evidence::AgentSigningKeyBinding,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AgentRuntimeBindings {
    pub open_handle: Option<OpenAgentPairingHandle>,
    pub active_binding: Option<ActiveAgentRuntimeBinding>,
}

impl AgentPairingState {
    pub fn new(
        id: String,
        controller_id: String,
        principal_control_realm_id: String,
        controller_authorization_ref: DidUrl,
        state: AgentLifecycleState,
        created_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            controller_id,
            principal_control_realm_id,
            controller_authorization_ref,
            display_name: None,
            agent_slug: None,
            avatar_blob_ref: None,
            state,
            requested_scope: None,
            accountability: None,
            provision_event_refs: None,
            pairing_request_id: None,
            paired_pairing_request_id: None,
            paired_request_digest: None,
            pending_pairing_commit_intent: None,
            pairing_code: None,
            pairing_expires_at: None,
            approval_request_id: None,
            controller_account_id: None,
            recipient_service_id: None,
            runtime_key_binding_digest: None,
            runtime_public_key_digest: None,
            runtime_attestation_digest: None,
            approval_notification_id: None,
            runtime_key_request: None,
            approval_requested_at: None,
            authorized_event_ref: None,
            authorized_verification_method: None,
            authorized_public_key_digest: None,
            authorized_signing_key_binding: None,
            state_changed_at: Some(created_at),
            created_at,
            updated_at: created_at,
        }
    }

    /// Reconstruct the two protocol states hidden behind the flat persistence
    /// columns. Partial tuples are rejected instead of being interpreted as a
    /// weaker state.
    pub fn runtime_bindings(&self) -> Result<AgentRuntimeBindings, String> {
        let active_binding = match self.authorized_event_ref.as_ref() {
            Some(authorized_event_ref) => {
                let completed_pairing_request_id =
                    self.paired_pairing_request_id.clone().ok_or_else(|| {
                        "active Agent runtime binding is missing paired_pairing_request_id"
                            .to_owned()
                    })?;
                let authorized_event_ref =
                    EventId::new(authorized_event_ref.clone()).map_err(|error| {
                        format!("active Agent runtime authorized_event_ref is invalid: {error}")
                    })?;
                let verification_method = self
                    .authorized_verification_method
                    .clone()
                    .ok_or_else(|| {
                        "active Agent runtime binding is missing verification_method".to_owned()
                    })
                    .and_then(|value| {
                        DidUrl::new(value).map_err(|error| {
                            format!("active Agent runtime verification_method is invalid: {error}")
                        })
                    })?;
                let public_key_digest = self
                    .authorized_public_key_digest
                    .clone()
                    .ok_or_else(|| {
                        "active Agent runtime binding is missing public_key_digest".to_owned()
                    })
                    .and_then(|value| {
                        Hash::new(value).map_err(|error| {
                            format!("active Agent runtime public_key_digest is invalid: {error}")
                        })
                    })?;
                let signing_key_binding =
                    self.authorized_signing_key_binding.clone().ok_or_else(|| {
                        "active Agent runtime binding is missing signing_key_binding".to_owned()
                    })?;
                // `authorized_public_key_digest` belongs to the public
                // authorization domain: it is the digest the controller-signed
                // `ak.agent.key.authorize` payload binds, i.e. the hash of the
                // raw 32-byte Ed25519 key. The private pairing-request JWK
                // digest is a deliberately distinct domain and lives in
                // `runtime_public_key_digest`; recomputing it here would never
                // match the stored column.
                let binding_authorization_public_key_digest =
                    arkret_signatures::agent_evidence::agent_signing_public_key_digest(
                        &signing_key_binding.public_key,
                    )
                    .map_err(|reason| {
                        format!(
                            "active Agent signing_key_binding public key is invalid: {reason:?}"
                        )
                    })?;
                if signing_key_binding.agent_id.as_str() != self.id
                    || signing_key_binding.agent_key_authorize_event_id != authorized_event_ref
                    || signing_key_binding.verification_method != verification_method
                    || signing_key_binding.public_key_digest != public_key_digest
                    || binding_authorization_public_key_digest != public_key_digest
                {
                    return Err(
                        "active Agent runtime binding fields do not match signing_key_binding"
                            .to_owned(),
                    );
                }
                Some(ActiveAgentRuntimeBinding {
                    completed_pairing_request_id,
                    authorized_event_ref,
                    verification_method,
                    public_key_digest,
                    signing_key_binding,
                })
            }
            None => {
                if self.paired_pairing_request_id.is_some()
                    || self.authorized_verification_method.is_some()
                    || self.authorized_public_key_digest.is_some()
                    || self.authorized_signing_key_binding.is_some()
                {
                    return Err(
                        "Agent runtime authorization columns contain a partial active binding"
                            .to_owned(),
                    );
                }
                None
            }
        };

        let open_handle = match self.pairing_request_id.as_ref() {
            Some(pairing_request_id)
                if self.paired_pairing_request_id.as_deref()
                    != Some(pairing_request_id.as_str()) =>
            {
                let pairing_code = self.pairing_code.clone().ok_or_else(|| {
                    "open Agent pairing handle is missing pairing_code".to_owned()
                })?;
                let expires_at = self.pairing_expires_at.ok_or_else(|| {
                    "open Agent pairing handle is missing pairing_expires_at".to_owned()
                })?;
                if self.runtime_key_request.as_ref().is_some_and(|request| {
                    request.pairing_request_id.as_str() != pairing_request_id.as_str()
                        || request.agent_id.as_str() != self.id
                }) {
                    return Err(
                        "pending Agent runtime key request does not match its open handle"
                            .to_owned(),
                    );
                }
                Some(OpenAgentPairingHandle {
                    pairing_request_id: pairing_request_id.clone(),
                    pairing_code,
                    expires_at,
                    pending_runtime_key_request: self.runtime_key_request.clone(),
                })
            }
            _ => {
                if self.runtime_key_request.is_some() {
                    return Err(
                        "pending Agent runtime key request has no unconsumed pairing handle"
                            .to_owned(),
                    );
                }
                None
            }
        };

        Ok(AgentRuntimeBindings {
            open_handle,
            active_binding,
        })
    }
}

/// Service-owned projection of a server-mediated device-pairing short-link
/// request. Mirrors the storage `DevicePairingRecord`; the port maps between
/// the two so the service layer stays storage-crate agnostic.
#[derive(Clone, Debug, PartialEq)]
pub struct DevicePairingState {
    pub device_pairing_request_id: String,
    pub pairing_code: String,
    pub new_device_pubkey: Value,
    pub client_nonce: String,
    pub gate_audience: String,
    pub server_nonce: String,
    pub display_name: Option<String>,
    pub device_metadata: Option<Value>,
    pub state: String,
    pub device_id: Option<String>,
    pub authorized_by_actor_id: Option<String>,
    pub authorized_event_ref: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[async_trait]
pub trait DevicePairingPort: Send + Sync {
    async fn stage(&self, record: DevicePairingState) -> ServiceResult<()>;
    async fn get(
        &self,
        device_pairing_request_id: &str,
    ) -> ServiceResult<Option<DevicePairingState>>;
    async fn commit_authorization(
        &self,
        device_pairing_request_id: &str,
        pairing_code: &str,
        new_device_pubkey: PublicKey,
        device_id: &str,
        authorized_by_actor_id: &str,
        authorized_event_ref: &str,
        changed_at: DateTime<Utc>,
    ) -> ServiceResult<bool>;
    async fn prune_expired_before(&self, cutoff: DateTime<Utc>) -> ServiceResult<u64>;
}

/// Minimal façade over the device-pairing short-link store: stage a new
/// account-less request, look one up, flip it to authorized once a verified
/// sibling drives `ak.gate.account.command.pair_device`, and prune expired rows.
#[derive(Clone)]
pub struct DevicePairingService {
    pairing: Arc<dyn DevicePairingPort>,
}

impl DevicePairingService {
    pub fn new(pairing: Arc<dyn DevicePairingPort>) -> Self {
        Self { pairing }
    }

    pub async fn stage(&self, record: DevicePairingState) -> ServiceResult<()> {
        self.pairing.stage(record).await
    }

    pub async fn get(
        &self,
        device_pairing_request_id: &str,
    ) -> ServiceResult<Option<DevicePairingState>> {
        self.pairing.get(device_pairing_request_id).await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn commit_authorization(
        &self,
        device_pairing_request_id: &str,
        pairing_code: &str,
        new_device_pubkey: PublicKey,
        device_id: &str,
        authorized_by_actor_id: &str,
        authorized_event_ref: &str,
        changed_at: DateTime<Utc>,
    ) -> ServiceResult<bool> {
        self.pairing
            .commit_authorization(
                device_pairing_request_id,
                pairing_code,
                new_device_pubkey,
                device_id,
                authorized_by_actor_id,
                authorized_event_ref,
                changed_at,
            )
            .await
    }

    pub async fn prune_expired_before(&self, cutoff: DateTime<Utc>) -> ServiceResult<u64> {
        self.pairing.prune_expired_before(cutoff).await
    }
}

#[derive(Clone, Debug)]
pub struct StoreAgentRuntimeApprovalCommand {
    pub agent_id: String,
    pub pairing_request_id: OpaqueLocalId,
    pub approval_request_id: OpaqueLocalId,
    pub approval_notification_id: String,
    pub approval_requested_at: DateTime<Utc>,
    pub controller_account_id: String,
    pub recipient_service_id: String,
    pub runtime_key_binding_digest: String,
    pub runtime_public_key_digest: String,
    pub runtime_attestation_digest: String,
    pub runtime_key_request:
        arkret_models_collaboration::agent_operations::AgentRuntimeApprovalControllerProjection,
}

pub type EnqueueAgentRuntimeMessageCommand = soland_storage::EnqueueAgentRuntimeMessage;
pub type AgentRuntimeEnqueueResult = soland_storage::AgentRuntimeEnqueueOutcome;

#[async_trait]
pub trait AgentPairingPort: Send + Sync {
    async fn pairing_record(
        &self,
        pairing_request_id: &str,
    ) -> ServiceResult<Option<AgentPairingState>>;
    async fn agent(&self, agent_id: &str) -> ServiceResult<Option<AgentPairingState>>;
    async fn agents_for_controller(
        &self,
        controller_id: &str,
    ) -> ServiceResult<Vec<AgentPairingState>>;
    async fn save_agent(&self, agent: AgentPairingState) -> ServiceResult<()>;
    async fn store_runtime_approval(
        &self,
        command: &StoreAgentRuntimeApprovalCommand,
    ) -> ServiceResult<Option<AgentPairingState>>;
    async fn activate_runtime_if_current(
        &self,
        command: &ActivateAgentRuntimeCommand,
    ) -> ServiceResult<bool>;
    async fn record_pairing_commit_intent(
        &self,
        command: &RecordAgentPairingCommitIntentCommand,
    ) -> ServiceResult<Option<AgentPairingState>>;
    async fn clear_approval_notification_if_current(
        &self,
        agent_id: &str,
        approval_request_id: &str,
    ) -> ServiceResult<bool>;
    async fn issue_provisioning_abandonment_challenge(
        &self,
        command: &soland_storage::IssueAgentProvisioningAbandonmentChallenge,
    ) -> ServiceResult<soland_storage::AgentProvisioningAbandonmentWriteOutcome>;
    async fn confirm_provisioning_abandonment(
        &self,
        command: &soland_storage::ConfirmAgentProvisioningAbandonment,
    ) -> ServiceResult<soland_storage::AgentProvisioningAbandonmentWriteOutcome>;
    async fn enqueue_runtime_message_if_current(
        &self,
        command: &EnqueueAgentRuntimeMessageCommand,
    ) -> ServiceResult<AgentRuntimeEnqueueResult>;
}

#[derive(Clone, Debug)]
pub struct AgentSidecarState {
    pub sidecar_id: String,
    pub realm_id: String,
    pub controller_id: String,
    pub state: String,
    pub state_changed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentSidecarContextState {
    pub sidecar_id: String,
    pub normalized_context_ref_digest: String,
    pub normalized_context_ref: Value,
    pub version: i64,
    pub predecessor_event_ref: Option<String>,
    pub attach_event_ref: String,
    pub created_at: DateTime<Utc>,
}

#[async_trait]
pub trait SidecarPort: Send + Sync {
    async fn ensure_sidecar(&self, sidecar: AgentSidecarState) -> ServiceResult<AgentSidecarState>;
    async fn sidecar(&self, sidecar_id: &str) -> ServiceResult<Option<AgentSidecarState>>;
    async fn sidecar_for_realm_controller(
        &self,
        realm_id: &str,
        controller_id: &str,
    ) -> ServiceResult<Option<AgentSidecarState>>;
    async fn sidecars_for_controller(
        &self,
        controller_id: &str,
        realm_id: Option<&str>,
    ) -> ServiceResult<Vec<AgentSidecarState>>;
    async fn ensure_context(
        &self,
        context: AgentSidecarContextState,
    ) -> ServiceResult<AgentSidecarContextState>;
    async fn context(
        &self,
        sidecar_id: &str,
        digest: &str,
    ) -> ServiceResult<Option<AgentSidecarContextState>>;
}

#[derive(Clone)]
pub struct AgentPairingService {
    pairing: Arc<dyn AgentPairingPort>,
    sidecars: Arc<dyn SidecarPort>,
}

#[derive(Clone, Debug)]
pub struct RecoveryPolicyState {
    pub policy_id: String,
    pub principal_id: String,
    pub version: u32,
    pub acceptance_basis: LeaseBasisRef,
    pub trust_domain: String,
    pub allowed_proof_kinds: Vec<String>,
    pub supersedes: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub issued_at: DateTime<Utc>,
    pub raw_payload: Value,
    pub accepted_at: DateTime<Utc>,
    pub verification_method: String,
}

#[derive(Clone, Debug)]
pub struct PublishRecoveryPolicyCommand {
    pub policy: RecoveryPolicyState,
}

#[derive(Clone, Debug)]
pub enum PublishRecoveryPolicyResult {
    // Boxed: the accepted policy is the only large payload here.
    Accepted(Box<RecoveryPolicyState>),
    GenesisVersionInvalid {
        actual: u32,
    },
    VersionNotMonotonic {
        actual: u32,
        current: u32,
    },
    SupersedesInvalid {
        actual: Option<String>,
        current_policy_id: String,
    },
}

#[async_trait]
pub trait RecoveryPolicyPort: Send + Sync {
    async fn active_policy(&self, principal_id: &str)
    -> ServiceResult<Option<RecoveryPolicyState>>;
    async fn policy_history(&self, principal_id: &str) -> ServiceResult<Vec<RecoveryPolicyState>>;
    async fn insert_policy(&self, policy: RecoveryPolicyState) -> ServiceResult<()>;
}

#[derive(Clone)]
pub struct RecoveryPolicyService {
    policies: Arc<dyn RecoveryPolicyPort>,
}

impl RecoveryPolicyService {
    pub fn new(policies: Arc<dyn RecoveryPolicyPort>) -> Self {
        Self { policies }
    }

    pub async fn active_policy(
        &self,
        principal_id: &str,
    ) -> ServiceResult<Option<RecoveryPolicyState>> {
        self.policies.active_policy(principal_id).await
    }

    pub async fn policy_history(
        &self,
        principal_id: &str,
    ) -> ServiceResult<Vec<RecoveryPolicyState>> {
        self.policies.policy_history(principal_id).await
    }

    pub async fn publish_policy(
        &self,
        command: PublishRecoveryPolicyCommand,
    ) -> ServiceResult<PublishRecoveryPolicyResult> {
        let policy = command.policy;
        let existing = self.policies.active_policy(&policy.principal_id).await?;
        if let Some(existing) = existing {
            if policy.version <= existing.version {
                return Ok(PublishRecoveryPolicyResult::VersionNotMonotonic {
                    actual: policy.version,
                    current: existing.version,
                });
            }
            if policy.supersedes.as_deref() != Some(existing.policy_id.as_str()) {
                return Ok(PublishRecoveryPolicyResult::SupersedesInvalid {
                    actual: policy.supersedes,
                    current_policy_id: existing.policy_id,
                });
            }
        } else if policy.version != 1 {
            return Ok(PublishRecoveryPolicyResult::GenesisVersionInvalid {
                actual: policy.version,
            });
        }
        self.policies.insert_policy(policy.clone()).await?;
        Ok(PublishRecoveryPolicyResult::Accepted(Box::new(policy)))
    }
}

#[derive(Clone, Debug)]
pub struct RecoverySessionState {
    pub recovery_session_id: String,
    pub principal_id: String,
    pub principal_server_id: String,
    pub requesting_device_id: String,
    pub trust_domain: String,
    pub policy_id: String,
    pub policy_version: u32,
    pub identity_model: RecoveryIdentityModel,
    pub current_device_generation_ref: Option<NonEmptyString>,
    pub device_generation_status: Option<DeviceGenerationStatus>,
    pub registry_head: Option<Hash>,
    pub accepted_seal_frontier: Option<DeviceReanchorPreFenceSealFrontier>,
    pub policy_payload: Value,
    pub publication_authority_context: RecoveryPublicationAuthorityContext,
    pub publication_authority_context_digest: Hash,
    pub challenge: String,
    pub state: String,
    pub proof_payload: Option<Value>,
    pub transaction_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[async_trait]
pub trait RecoverySessionPort: Send + Sync {
    async fn session(
        &self,
        recovery_session_id: &str,
    ) -> ServiceResult<Option<RecoverySessionState>>;
    async fn insert_session(&self, session: RecoverySessionState) -> ServiceResult<()>;
    async fn update_session(&self, session: RecoverySessionState) -> ServiceResult<()>;
}

#[derive(Clone)]
pub struct RecoverySessionService {
    sessions: Arc<dyn RecoverySessionPort>,
}

impl RecoverySessionService {
    pub fn new(sessions: Arc<dyn RecoverySessionPort>) -> Self {
        Self { sessions }
    }

    pub async fn session(
        &self,
        recovery_session_id: &str,
    ) -> ServiceResult<Option<RecoverySessionState>> {
        self.sessions.session(recovery_session_id).await
    }

    pub async fn create_session(&self, session: RecoverySessionState) -> ServiceResult<()> {
        self.sessions.insert_session(session).await
    }

    pub async fn save_session(&self, session: RecoverySessionState) -> ServiceResult<()> {
        self.sessions.update_session(session).await
    }
}

#[derive(Clone, Debug)]
pub struct SecurityTransactionState {
    pub canonical_request: Vec<u8>,
    pub resource: arkret_wire::SecurityTransaction,
}

#[derive(Clone, Debug)]
pub struct SecurityTransactionStepOutcomeState {
    pub transaction_id: String,
    pub step: arkret_wire::SecurityTransactionStep,
    pub canonical_request: Vec<u8>,
    pub response: Value,
    pub participant_outcome: Option<Value>,
}

#[derive(Clone, Debug)]
pub struct SecurityTransactionStepAttemptState {
    pub transaction_id: String,
    pub step: arkret_wire::SecurityTransactionStep,
    pub canonical_request: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct BackupSeriesEraseProgressState {
    pub transaction_id: String,
    pub canonical_request: Vec<u8>,
    pub outcome: arkret_models_crypto::BackupSeriesEraseOutcome,
}

#[async_trait]
pub trait SecurityTransactionPort: Send + Sync {
    async fn create(
        &self,
        transaction: SecurityTransactionState,
    ) -> ServiceResult<SecurityTransactionState>;
    async fn transaction(
        &self,
        transaction_id: &str,
    ) -> ServiceResult<Option<SecurityTransactionState>>;
    async fn save(&self, transaction: SecurityTransactionState) -> ServiceResult<()>;
    async fn step_outcome(
        &self,
        transaction_id: &str,
        step: arkret_wire::SecurityTransactionStep,
    ) -> ServiceResult<Option<SecurityTransactionStepOutcomeState>>;
    async fn step_attempt(
        &self,
        transaction_id: &str,
        step: arkret_wire::SecurityTransactionStep,
    ) -> ServiceResult<Option<SecurityTransactionStepAttemptState>>;
    async fn begin_step(
        &self,
        attempt: SecurityTransactionStepAttemptState,
    ) -> ServiceResult<SecurityTransactionStepAttemptState>;
    async fn accept_step(
        &self,
        transaction: SecurityTransactionState,
        outcome: SecurityTransactionStepOutcomeState,
    ) -> ServiceResult<SecurityTransactionStepOutcomeState>;
    async fn backup_erase_progress(
        &self,
        transaction_id: &str,
    ) -> ServiceResult<Option<BackupSeriesEraseProgressState>>;
    async fn begin_backup_erase(
        &self,
        progress: BackupSeriesEraseProgressState,
    ) -> ServiceResult<BackupSeriesEraseProgressState>;
    async fn update_backup_erase(
        &self,
        progress: BackupSeriesEraseProgressState,
    ) -> ServiceResult<BackupSeriesEraseProgressState>;
}

#[derive(Clone)]
pub struct SecurityTransactionService {
    transactions: Arc<dyn SecurityTransactionPort>,
}

impl SecurityTransactionService {
    pub fn new(transactions: Arc<dyn SecurityTransactionPort>) -> Self {
        Self { transactions }
    }

    pub async fn create(
        &self,
        transaction: SecurityTransactionState,
    ) -> ServiceResult<SecurityTransactionState> {
        self.transactions.create(transaction).await
    }

    pub async fn transaction(
        &self,
        transaction_id: &str,
    ) -> ServiceResult<Option<SecurityTransactionState>> {
        self.transactions.transaction(transaction_id).await
    }

    pub async fn save(&self, transaction: SecurityTransactionState) -> ServiceResult<()> {
        self.transactions.save(transaction).await
    }

    pub async fn step_outcome(
        &self,
        transaction_id: &str,
        step: arkret_wire::SecurityTransactionStep,
    ) -> ServiceResult<Option<SecurityTransactionStepOutcomeState>> {
        self.transactions.step_outcome(transaction_id, step).await
    }

    pub async fn step_attempt(
        &self,
        transaction_id: &str,
        step: arkret_wire::SecurityTransactionStep,
    ) -> ServiceResult<Option<SecurityTransactionStepAttemptState>> {
        self.transactions.step_attempt(transaction_id, step).await
    }

    pub async fn begin_step(
        &self,
        attempt: SecurityTransactionStepAttemptState,
    ) -> ServiceResult<SecurityTransactionStepAttemptState> {
        self.transactions.begin_step(attempt).await
    }

    pub async fn accept_step(
        &self,
        transaction: SecurityTransactionState,
        outcome: SecurityTransactionStepOutcomeState,
    ) -> ServiceResult<SecurityTransactionStepOutcomeState> {
        self.transactions.accept_step(transaction, outcome).await
    }

    pub async fn backup_erase_progress(
        &self,
        transaction_id: &str,
    ) -> ServiceResult<Option<BackupSeriesEraseProgressState>> {
        self.transactions
            .backup_erase_progress(transaction_id)
            .await
    }

    pub async fn begin_backup_erase(
        &self,
        progress: BackupSeriesEraseProgressState,
    ) -> ServiceResult<BackupSeriesEraseProgressState> {
        self.transactions.begin_backup_erase(progress).await
    }

    pub async fn update_backup_erase(
        &self,
        progress: BackupSeriesEraseProgressState,
    ) -> ServiceResult<BackupSeriesEraseProgressState> {
        self.transactions.update_backup_erase(progress).await
    }
}

#[async_trait]
pub trait AgentParticipationPort: Send + Sync {
    async fn compare_and_swap_selection(
        &self,
        selection: Value,
        expected_version: u64,
    ) -> ServiceResult<bool>;
    async fn selections(&self, agent_id: &str) -> ServiceResult<Vec<Value>>;
    async fn ceilings(&self, scope_keys: &[String]) -> ServiceResult<Vec<Value>>;
    async fn store_ceiling(&self, ceiling: Value) -> ServiceResult<()>;
}

#[derive(Clone)]
pub struct AgentParticipationService {
    participation: Arc<dyn AgentParticipationPort>,
}

impl AgentParticipationService {
    pub fn new(participation: Arc<dyn AgentParticipationPort>) -> Self {
        Self { participation }
    }

    pub async fn compare_and_swap_selection(
        &self,
        selection: Value,
        expected_version: u64,
    ) -> ServiceResult<bool> {
        self.participation
            .compare_and_swap_selection(selection, expected_version)
            .await
    }

    pub async fn selections(&self, agent_id: &str) -> ServiceResult<Vec<Value>> {
        self.participation.selections(agent_id).await
    }

    pub async fn ceilings(&self, scope_keys: &[String]) -> ServiceResult<Vec<Value>> {
        self.participation.ceilings(scope_keys).await
    }

    pub async fn store_ceiling(&self, ceiling: Value) -> ServiceResult<()> {
        self.participation.store_ceiling(ceiling).await
    }
}

/// Re-exported so the HTTP layer can name a delete challenge without depending
/// on `soland-storage` directly (it is a dev-dependency there): the service
/// facade is the only boundary the routing code crosses.
pub use soland_storage::KeyBackupDeleteChallengeRecord;

#[async_trait]
pub trait KeyBackupPort: Send + Sync {
    async fn backup(&self, backup_id: &str) -> ServiceResult<Option<Value>>;
    async fn backups_for_actor(&self, actor_id: &str) -> ServiceResult<Vec<Value>>;
    async fn store_backup(&self, backup_id: String, payload: Value) -> ServiceResult<()>;
    async fn delete_backup(&self, backup_id: &str) -> ServiceResult<bool>;
    async fn issue_delete_challenge(
        &self,
        record: soland_storage::KeyBackupDeleteChallengeRecord,
        now: DateTime<Utc>,
    ) -> ServiceResult<soland_storage::KeyBackupDeleteChallengeRecord>;
    async fn delete_challenge(
        &self,
        challenge_id: &str,
    ) -> ServiceResult<Option<soland_storage::KeyBackupDeleteChallengeRecord>>;
    async fn consume_delete_challenge(
        &self,
        challenge_id: &str,
        now: DateTime<Utc>,
    ) -> ServiceResult<bool>;
    async fn prune_expired_delete_challenges(&self, now: DateTime<Utc>) -> ServiceResult<usize>;
}

#[derive(Clone)]
pub struct KeyBackupService {
    backups: Arc<dyn KeyBackupPort>,
}

#[derive(Clone, Debug)]
pub struct AgentSessionState {
    pub granted_scope: Vec<String>,
    pub scope_details: Value,
    pub freshness_state: arkret_wire::FreshnessState,
}

#[derive(Clone, Debug)]
pub struct SessionGrantAuthorizationState {
    pub grant_id: arkret_identifiers::SessionGrantId,
    pub issuer: String,
    /// Scopes the Account Authority bound into the presented grant. They are
    /// the only wire-visible statement about what the grant was authorized
    /// for, so deployment policies that gate a high-risk self-service action
    /// on a step-up authentication (`account-lifecycle.md` §8.1) read them
    /// here rather than re-deriving authentication strength locally.
    pub scopes: Vec<String>,
    pub credential_class: arkret_models_identity::session_credential::SessionGrantCredentialClass,
    pub holder_binding: arkret_models_identity::session_credential::SessionGrantHolderBinding,
    pub device_binding:
        Option<arkret_models_identity::session_credential::SessionGrantDeviceBinding>,
    pub cnf_jkt: String,
}

#[derive(Clone, Debug)]
pub struct SessionIdentityState {
    pub token_hash: String,
    pub actor: String,
    pub device_id: String,
    pub audience: String,
    pub session_public_key: Option<String>,
    pub agent_session: Option<AgentSessionState>,
    /// Present only for request-scoped `ak.session.grant` authentication. This
    /// preserves the credential class and closed bootstrap binding through
    /// authorization; local/dev sessions deliberately carry `None`.
    pub session_grant: Option<SessionGrantAuthorizationState>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[async_trait]
pub trait SessionIdentityPort: Send + Sync {
    async fn session(&self, token_hash: &str) -> ServiceResult<Option<SessionIdentityState>>;
    async fn sessions(&self) -> ServiceResult<Vec<SessionIdentityState>>;
    async fn save_session(&self, session: SessionIdentityState) -> ServiceResult<()>;
    async fn revoke_session(
        &self,
        token_hash: &str,
        revoked_at: DateTime<Utc>,
    ) -> ServiceResult<Option<SessionIdentityState>>;
    async fn revoke_actor_sessions(
        &self,
        actor_id: &str,
        revoked_at: DateTime<Utc>,
    ) -> ServiceResult<usize>;
    async fn revoke_actor_device_sessions(
        &self,
        actor_id: &str,
        device_id: &str,
        revoked_at: DateTime<Utc>,
    ) -> ServiceResult<usize>;
}

#[derive(Clone)]
pub struct SessionService {
    sessions: Arc<dyn SessionIdentityPort>,
}

impl SessionService {
    pub fn new(sessions: Arc<dyn SessionIdentityPort>) -> Self {
        Self { sessions }
    }

    pub async fn session(&self, token_hash: &str) -> ServiceResult<Option<SessionIdentityState>> {
        self.sessions.session(token_hash).await
    }

    pub async fn create_session(&self, session: SessionIdentityState) -> ServiceResult<()> {
        self.sessions.save_session(session).await
    }

    pub async fn revoke_session(
        &self,
        token_hash: &str,
        revoked_at: DateTime<Utc>,
    ) -> ServiceResult<Option<SessionIdentityState>> {
        self.sessions.revoke_session(token_hash, revoked_at).await
    }

    pub async fn revoke_actor_sessions(
        &self,
        actor_id: &str,
        revoked_at: DateTime<Utc>,
    ) -> ServiceResult<usize> {
        self.sessions
            .revoke_actor_sessions(actor_id, revoked_at)
            .await
    }

    pub async fn revoke_actor_device_sessions(
        &self,
        actor_id: &str,
        device_id: &str,
        revoked_at: DateTime<Utc>,
    ) -> ServiceResult<usize> {
        self.sessions
            .revoke_actor_device_sessions(actor_id, device_id, revoked_at)
            .await
    }

    pub async fn active_delegated_sessions_for_actor(
        &self,
        actor_id: &str,
    ) -> ServiceResult<usize> {
        Ok(self
            .sessions
            .sessions()
            .await?
            .into_iter()
            .filter(|session| {
                session.actor == actor_id
                    && session.revoked_at.is_none()
                    && session.agent_session.is_some()
            })
            .count())
    }
}

impl KeyBackupService {
    pub fn new(backups: Arc<dyn KeyBackupPort>) -> Self {
        Self { backups }
    }

    pub async fn backup(&self, backup_id: &str) -> ServiceResult<Option<Value>> {
        self.backups.backup(backup_id).await
    }

    pub async fn backups_for_actor(&self, actor_id: &str) -> ServiceResult<Vec<Value>> {
        self.backups.backups_for_actor(actor_id).await
    }

    pub async fn store_backup(&self, backup_id: String, payload: Value) -> ServiceResult<()> {
        self.backups.store_backup(backup_id, payload).await
    }

    /// Issue, or re-issue verbatim, the delete challenge for one
    /// `(principal_id, backup_id, request_id)` (`key-management.md` §7.8.1).
    pub async fn issue_delete_challenge(
        &self,
        record: soland_storage::KeyBackupDeleteChallengeRecord,
        now: DateTime<Utc>,
    ) -> ServiceResult<soland_storage::KeyBackupDeleteChallengeRecord> {
        self.backups.issue_delete_challenge(record, now).await
    }

    pub async fn delete_challenge(
        &self,
        challenge_id: &str,
    ) -> ServiceResult<Option<soland_storage::KeyBackupDeleteChallengeRecord>> {
        self.backups.delete_challenge(challenge_id).await
    }

    /// Consume a challenge exactly once. `false` means it was already consumed
    /// or never existed.
    pub async fn consume_delete_challenge(
        &self,
        challenge_id: &str,
        now: DateTime<Utc>,
    ) -> ServiceResult<bool> {
        self.backups
            .consume_delete_challenge(challenge_id, now)
            .await
    }

    pub async fn prune_expired_delete_challenges(
        &self,
        now: DateTime<Utc>,
    ) -> ServiceResult<usize> {
        self.backups.prune_expired_delete_challenges(now).await
    }

    pub async fn delete_backup(&self, backup_id: &str) -> ServiceResult<bool> {
        self.backups.delete_backup(backup_id).await
    }
}

impl AgentPairingService {
    pub fn new(pairing: Arc<dyn AgentPairingPort>, sidecars: Arc<dyn SidecarPort>) -> Self {
        Self { pairing, sidecars }
    }

    pub async fn pairing_record(
        &self,
        pairing_request_id: &str,
    ) -> ServiceResult<Option<AgentPairingState>> {
        self.pairing.pairing_record(pairing_request_id).await
    }

    pub async fn agent(&self, agent_id: &str) -> ServiceResult<Option<AgentPairingState>> {
        self.pairing.agent(agent_id).await
    }

    pub async fn agents_for_controller(
        &self,
        controller_id: &str,
    ) -> ServiceResult<Vec<AgentPairingState>> {
        self.pairing.agents_for_controller(controller_id).await
    }

    pub async fn save_agent(&self, agent: AgentPairingState) -> ServiceResult<()> {
        self.pairing.save_agent(agent).await
    }

    pub async fn store_runtime_approval(
        &self,
        command: &StoreAgentRuntimeApprovalCommand,
    ) -> ServiceResult<Option<AgentPairingState>> {
        self.pairing.store_runtime_approval(command).await
    }

    pub async fn activate_runtime(
        &self,
        command: &ActivateAgentRuntimeCommand,
    ) -> ServiceResult<bool> {
        self.pairing.activate_runtime_if_current(command).await
    }

    pub async fn record_pairing_commit_intent(
        &self,
        command: &RecordAgentPairingCommitIntentCommand,
    ) -> ServiceResult<Option<AgentPairingState>> {
        self.pairing.record_pairing_commit_intent(command).await
    }

    pub async fn clear_approval_notification(
        &self,
        agent_id: &str,
        approval_request_id: &str,
    ) -> ServiceResult<bool> {
        self.pairing
            .clear_approval_notification_if_current(agent_id, approval_request_id)
            .await
    }

    pub async fn issue_provisioning_abandonment_challenge(
        &self,
        command: &soland_storage::IssueAgentProvisioningAbandonmentChallenge,
    ) -> ServiceResult<soland_storage::AgentProvisioningAbandonmentWriteOutcome> {
        self.pairing
            .issue_provisioning_abandonment_challenge(command)
            .await
    }

    pub async fn confirm_provisioning_abandonment(
        &self,
        command: &soland_storage::ConfirmAgentProvisioningAbandonment,
    ) -> ServiceResult<soland_storage::AgentProvisioningAbandonmentWriteOutcome> {
        self.pairing.confirm_provisioning_abandonment(command).await
    }

    pub async fn enqueue_runtime_message_if_current(
        &self,
        command: &EnqueueAgentRuntimeMessageCommand,
    ) -> ServiceResult<AgentRuntimeEnqueueResult> {
        self.pairing
            .enqueue_runtime_message_if_current(command)
            .await
    }

    pub async fn ensure_sidecar(
        &self,
        sidecar: AgentSidecarState,
    ) -> ServiceResult<AgentSidecarState> {
        self.sidecars.ensure_sidecar(sidecar).await
    }
    pub async fn sidecar(&self, sidecar_id: &str) -> ServiceResult<Option<AgentSidecarState>> {
        self.sidecars.sidecar(sidecar_id).await
    }
    pub async fn sidecar_for_realm_controller(
        &self,
        realm_id: &str,
        controller_id: &str,
    ) -> ServiceResult<Option<AgentSidecarState>> {
        self.sidecars
            .sidecar_for_realm_controller(realm_id, controller_id)
            .await
    }
    pub async fn sidecars_for_controller(
        &self,
        controller_id: &str,
        realm_id: Option<&str>,
    ) -> ServiceResult<Vec<AgentSidecarState>> {
        self.sidecars
            .sidecars_for_controller(controller_id, realm_id)
            .await
    }
    pub async fn ensure_sidecar_context(
        &self,
        context: AgentSidecarContextState,
    ) -> ServiceResult<AgentSidecarContextState> {
        self.sidecars.ensure_context(context).await
    }
    pub async fn sidecar_context(
        &self,
        sidecar_id: &str,
        digest: &str,
    ) -> ServiceResult<Option<AgentSidecarContextState>> {
        self.sidecars.context(sidecar_id, digest).await
    }
}

impl IdentityService {
    pub fn new(
        accounts: Arc<dyn AccountLookupPort>,
        devices: Arc<dyn DeviceDirectoryPort>,
        agents: Arc<dyn AgentDirectoryPort>,
    ) -> Self {
        Self {
            accounts,
            devices,
            agents,
            account_registration_attempts: Arc::new(Mutex::new(BTreeMap::new())),
            account_lifecycles: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub fn account_registration_retry_after_ms(
        &self,
        actor_id: &str,
        max_attempts: u32,
        window_seconds: u64,
        now: DateTime<Utc>,
    ) -> Option<u64> {
        if max_attempts == 0 || window_seconds == 0 {
            return Some(0);
        }
        let window = chrono::Duration::seconds(window_seconds as i64);
        let mut attempts = self.account_registration_attempts.lock();
        let entry = attempts.entry(actor_id.to_owned()).or_insert((now, 0));
        if now.signed_duration_since(entry.0) >= window {
            *entry = (now, 0);
        }
        if entry.1 >= max_attempts {
            return Some(
                window
                    .checked_sub(&now.signed_duration_since(entry.0))
                    .unwrap_or_else(chrono::Duration::zero)
                    .num_milliseconds()
                    .max(0) as u64,
            );
        }
        entry.1 += 1;
        None
    }

    pub async fn find_account_by_actor(
        &self,
        query: FindAccountByActorQuery,
    ) -> ServiceResult<Option<AccountIdentity>> {
        self.accounts.find_account_by_actor(&query.actor_id).await
    }

    pub async fn register_account(&self, command: RegisterAccountCommand) -> ServiceResult<()> {
        self.accounts.register_account(command).await
    }

    pub async fn account(&self, actor_id: &str) -> ServiceResult<Option<AccountProfileState>> {
        self.accounts.account(actor_id).await
    }

    pub async fn accounts(&self) -> ServiceResult<Vec<AccountProfileState>> {
        self.accounts.accounts().await
    }

    pub async fn save_account(&self, account: AccountProfileState) -> ServiceResult<()> {
        self.accounts.save_account(account).await
    }

    pub async fn delete_account(&self, actor_id: &str) -> ServiceResult<()> {
        self.accounts.delete_account(actor_id).await
    }

    pub async fn account_localparts(
        &self,
        actor_id: &str,
    ) -> ServiceResult<Vec<AccountLocalpartState>> {
        self.accounts.account_localparts(actor_id).await
    }

    pub async fn localpart_owner(
        &self,
        localpart: &str,
    ) -> ServiceResult<Option<AccountLocalpartState>> {
        self.accounts.localpart_owner(localpart).await
    }

    pub async fn add_localpart(
        &self,
        actor_id: &str,
        localpart: &str,
        primary: bool,
    ) -> ServiceResult<AccountLocalpartState> {
        self.accounts
            .add_localpart(actor_id, localpart, primary)
            .await
    }

    pub async fn set_primary_localpart(
        &self,
        actor_id: &str,
        localpart: &str,
    ) -> ServiceResult<AccountLocalpartState> {
        self.accounts
            .set_primary_localpart(actor_id, localpart)
            .await
    }

    pub async fn remove_localpart(&self, actor_id: &str, localpart: &str) -> ServiceResult<()> {
        self.accounts.remove_localpart(actor_id, localpart).await
    }

    pub async fn clear_localparts(&self, actor_id: &str) -> ServiceResult<()> {
        self.accounts.clear_localparts(actor_id).await
    }

    pub async fn record_handle_release(
        &self,
        localpart: &str,
        released_at: DateTime<Utc>,
    ) -> ServiceResult<()> {
        self.accounts
            .record_handle_release(localpart, released_at)
            .await
    }

    pub async fn save_account_lifecycle(
        &self,
        actor_id: &str,
        lifecycle: AccountLifecycleState,
    ) -> ServiceResult<()> {
        self.accounts
            .save_account_lifecycle(actor_id, lifecycle.clone())
            .await?;
        if lifecycle.state == "active" {
            self.account_lifecycles.lock().remove(actor_id);
        } else {
            self.account_lifecycles
                .lock()
                .insert(actor_id.to_owned(), lifecycle);
        }
        Ok(())
    }

    pub async fn delete_account_lifecycle(&self, actor_id: &str) -> ServiceResult<()> {
        self.accounts.delete_account_lifecycle(actor_id).await?;
        self.account_lifecycles.lock().remove(actor_id);
        Ok(())
    }

    pub async fn hydrate_account_lifecycles(&self) -> ServiceResult<()> {
        let lifecycles = self.accounts.account_lifecycles().await?;
        *self.account_lifecycles.lock() = lifecycles
            .into_iter()
            .filter(|(_, lifecycle)| lifecycle.state != "active")
            .collect();
        Ok(())
    }

    pub fn account_lifecycle_status(&self, actor_id: &str) -> AccountStatus {
        self.account_lifecycles
            .lock()
            .get(actor_id)
            .map(|lifecycle| lifecycle_status_from_wire(&lifecycle.state))
            .unwrap_or(AccountStatus::Active)
    }

    pub fn account_lifecycle_state(&self, actor_id: &str) -> String {
        self.account_lifecycle_status(actor_id).as_str().to_owned()
    }

    /// Snapshot of every non-`active` account lifecycle record.
    ///
    /// The map is hydrated from durable storage at boot
    /// ([`Self::hydrate_account_lifecycles`]) and kept current by the save /
    /// delete paths, so reconciliation workers (e.g. the deactivation push
    /// fanout) can enumerate deactivated accounts without a storage scan.
    pub fn account_lifecycles_snapshot(&self) -> Vec<(String, AccountLifecycleState)> {
        self.account_lifecycles
            .lock()
            .iter()
            .map(|(actor_id, lifecycle)| (actor_id.clone(), lifecycle.clone()))
            .collect()
    }

    pub async fn list_active_device_actors(
        &self,
        _query: ListActiveDeviceActorsQuery,
    ) -> ServiceResult<Vec<String>> {
        self.devices.list_active_device_actors().await
    }

    pub async fn devices(&self) -> ServiceResult<Vec<DeviceIdentity>> {
        self.devices.devices().await
    }

    pub async fn find_device(
        &self,
        query: FindDeviceQuery,
    ) -> ServiceResult<Option<DeviceIdentity>> {
        self.devices
            .find_device(&query.actor_id, &query.device_id)
            .await
    }

    pub async fn save_device(&self, command: SaveDeviceCommand) -> ServiceResult<()> {
        self.devices.save_device(command).await
    }

    pub async fn save_device_if_absent(&self, device: DeviceIdentity) -> ServiceResult<bool> {
        self.devices.save_device_if_absent(device).await
    }

    pub async fn devices_for_actor(&self, actor_id: &str) -> ServiceResult<Vec<DeviceIdentity>> {
        self.devices.devices_for_actor(actor_id).await
    }

    pub async fn find_agent_controller(
        &self,
        query: FindAgentControllerQuery,
    ) -> ServiceResult<Option<AgentController>> {
        self.agents.find_agent_controller(&query.agent_id).await
    }
}

#[derive(Clone, Debug)]
pub struct DidDocumentState {
    pub did: String,
    pub did_document: Value,
    pub key_log_head: Option<String>,
    pub seq: u64,
    pub method_evidence: Value,
    pub fetched_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub const DID_DOCUMENT_HIGH_RISK_TTL_SECS: i64 = 15 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DidDocumentFreshness {
    Fresh,
    Stale,
}

pub fn evaluate_did_document_freshness(
    record: &DidDocumentState,
    now: DateTime<Utc>,
    max_age: chrono::Duration,
) -> DidDocumentFreshness {
    if now.signed_duration_since(record.fetched_at) > max_age {
        DidDocumentFreshness::Stale
    } else {
        DidDocumentFreshness::Fresh
    }
}

#[derive(Clone, Debug)]
pub struct DidLogEvent {
    pub event_digest: String,
    pub did: String,
    pub seq: u64,
    pub operation: Value,
    pub created_at: DateTime<Utc>,
}

/// Relationship between a verified pinned did:webvh version and the verified
/// head observed during the same history resolution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinnedDidVersionStatus {
    /// The requested version is the current verified head.
    Current,
    /// A later verified rotation exists. The pinned document remains usable
    /// only for proofs whose transcript names this exact historical version.
    Rotated,
    /// The verified history head deactivates the DID. No pinned version may be
    /// used to establish or refresh an active control relationship.
    Deactivated,
}

/// Method-history-verified did:webvh state selected by both native version id
/// and the canonical digest of that exact log entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedDidDocumentState {
    pub did: DidFullId,
    pub version_id: String,
    pub log_head_digest: Hash,
    pub document: Value,
    pub update_keys: Vec<String>,
    pub current_version_id: String,
    pub status: PinnedDidVersionStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PinnedDidResolutionError {
    #[error("pinned DID resolution requires did:webvh")]
    UnsupportedMethod,
    #[error("did:webvh method is disabled by resolver policy")]
    MethodNotAllowed,
    #[error("verified did:webvh history is unavailable")]
    HistoryUnavailable,
    #[error("did:webvh history could not be verified: {0}")]
    HistoryUnverifiable(String),
    #[error("requested did:webvh version was not found: {0}")]
    VersionNotFound(String),
    #[error("requested did:webvh version digest does not match verified history")]
    DigestMismatch,
}

/// Select a pinned state only after the SDK verifier has authenticated the
/// complete history. This deliberately never accepts a separately resolved
/// current document as evidence for a historical version.
pub fn select_pinned_did_webvh_state(
    did: &DidFullId,
    history: &arkret_identity::VerifiedDidWebvhLog,
    version_id: &str,
    log_head_digest: &Hash,
) -> Result<PinnedDidDocumentState, PinnedDidResolutionError> {
    if did.method() != "webvh" {
        return Err(PinnedDidResolutionError::UnsupportedMethod);
    }
    if history.entries.len() != history.raw_entries.len() || history.entries.is_empty() {
        return Err(PinnedDidResolutionError::HistoryUnverifiable(
            "verified history has inconsistent entry projections".to_owned(),
        ));
    }
    let selected_index = history
        .entries
        .iter()
        .position(|entry| entry.version_id == version_id)
        .ok_or_else(|| PinnedDidResolutionError::VersionNotFound(version_id.to_owned()))?;
    let selected_raw = &history.raw_entries[selected_index];
    let actual_digest = arkret_canonical::canonical_sha256(selected_raw).map_err(|error| {
        PinnedDidResolutionError::HistoryUnverifiable(format!(
            "pinned log entry digest failed: {error}"
        ))
    })?;
    if actual_digest != log_head_digest.as_str() {
        return Err(PinnedDidResolutionError::DigestMismatch);
    }

    let deactivated_index = history.entries.iter().position(|entry| {
        entry.parameters.get("deactivated").and_then(Value::as_bool) == Some(true)
    });
    if deactivated_index.is_some_and(|index| index + 1 != history.entries.len()) {
        return Err(PinnedDidResolutionError::HistoryUnverifiable(
            "did:webvh history continues after terminal deactivation".to_owned(),
        ));
    }
    let status = if deactivated_index.is_some() {
        PinnedDidVersionStatus::Deactivated
    } else if selected_index + 1 == history.entries.len() {
        PinnedDidVersionStatus::Current
    } else {
        PinnedDidVersionStatus::Rotated
    };
    let selected = &history.entries[selected_index];
    let update_keys = selected
        .parameters
        .get("updateKeys")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect();
    Ok(PinnedDidDocumentState {
        did: did.clone(),
        version_id: selected.version_id.clone(),
        log_head_digest: log_head_digest.clone(),
        document: selected.state.clone(),
        update_keys,
        current_version_id: history.head_version_id.clone(),
        status,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DidLogCommitResult {
    Accepted,
    Duplicate,
    Conflict,
}

#[derive(Clone, Debug)]
pub enum ServiceRegistrationCommitResult {
    Created(ServiceRegistrationOutcome),
    Existing(ServiceRegistrationOutcome),
    Conflict,
}

#[async_trait]
pub trait DidDocumentPort: Send + Sync {
    async fn document(&self, did: &str) -> ServiceResult<Option<DidDocumentState>>;
    async fn embedded_document(&self, local_id: &str) -> ServiceResult<Option<DidDocumentState>>;
    async fn log_events(&self, did: &str) -> ServiceResult<Vec<DidLogEvent>>;
    async fn store_document(&self, document: DidDocumentState) -> ServiceResult<()>;
    async fn append_log_event(&self, event: DidLogEvent) -> ServiceResult<()>;
    async fn service_registration(
        &self,
        key: &ServiceRegistrationKey,
    ) -> ServiceResult<Option<ServiceRegistrationOutcome>>;
    async fn commit_service_registration(
        &self,
        key: ServiceRegistrationKey,
        outcome: ServiceRegistrationOutcome,
        document: DidDocumentState,
        event: DidLogEvent,
    ) -> ServiceResult<ServiceRegistrationCommitResult>;
    async fn commit_log_operation(
        &self,
        expected_current_head: Option<String>,
        document: DidDocumentState,
        event: DidLogEvent,
    ) -> ServiceResult<DidLogCommitResult>;
}

#[async_trait]
pub trait DidResolverPort: arkret_identity::DidResolver + Send + Sync {
    async fn resolve_did_async(
        &self,
        did: &DidFullId,
    ) -> Result<arkret_identity::DidDocument, String>;
    async fn resolve_current_external_webvh_state(
        &self,
        did: &DidFullId,
    ) -> Result<PinnedDidDocumentState, PinnedDidResolutionError>;
    async fn resolve_external_pinned_webvh_state(
        &self,
        did: &DidFullId,
        version_id: &str,
        log_head_digest: &Hash,
    ) -> Result<PinnedDidDocumentState, PinnedDidResolutionError>;
    fn cache_document_state(
        &self,
        document: DidDocumentState,
    ) -> Result<arkret_identity::DidDocument, String>;
}

#[derive(Clone)]
pub struct DidService {
    documents: Arc<dyn DidDocumentPort>,
    resolver: Arc<dyn DidResolverPort>,
}

impl DidService {
    pub fn new(documents: Arc<dyn DidDocumentPort>, resolver: Arc<dyn DidResolverPort>) -> Self {
        Self {
            documents,
            resolver,
        }
    }

    pub fn resolver(&self) -> &dyn arkret_identity::DidResolver {
        self.resolver.as_ref()
    }

    pub fn shared_resolver(&self) -> Arc<dyn DidResolverPort> {
        self.resolver.clone()
    }

    pub async fn resolve_did(
        &self,
        did: &DidFullId,
    ) -> Result<arkret_identity::DidDocument, String> {
        if let Some(document) = self
            .documents
            .document(did.as_str())
            .await
            .map_err(|error| error.to_string())?
        {
            return self.resolver.cache_document_state(document);
        }
        self.resolver.resolve_did_async(did).await
    }

    /// Resolve a did:webvh document at an exact native version and canonical
    /// log-entry digest. Durable native history is preferred; external
    /// resolution is used only when no local log exists.
    pub async fn resolve_pinned_webvh_state(
        &self,
        did: &DidFullId,
        version_id: &str,
        log_head_digest: &Hash,
    ) -> Result<PinnedDidDocumentState, PinnedDidResolutionError> {
        if did.method() != "webvh" {
            return Err(PinnedDidResolutionError::UnsupportedMethod);
        }
        let mut local_events = self
            .documents
            .log_events(did.as_str())
            .await
            .map_err(|error| {
                PinnedDidResolutionError::HistoryUnverifiable(format!(
                    "local DID history lookup failed: {error}"
                ))
            })?;
        if local_events.is_empty() {
            return self
                .resolver
                .resolve_external_pinned_webvh_state(did, version_id, log_head_digest)
                .await;
        }
        local_events.sort_by_key(|event| event.seq);
        let mut raw_entries = Vec::with_capacity(local_events.len());
        for (index, event) in local_events.iter().enumerate() {
            let expected_seq = index as u64 + 1;
            if event.did != did.as_str() || event.seq != expected_seq {
                return Err(PinnedDidResolutionError::HistoryUnverifiable(
                    "local did:webvh log identity or sequence is inconsistent".to_owned(),
                ));
            }
            let canonical_digest =
                arkret_canonical::canonical_sha256(&event.operation).map_err(|error| {
                    PinnedDidResolutionError::HistoryUnverifiable(format!(
                        "local did:webvh event digest failed: {error}"
                    ))
                })?;
            if canonical_digest != event.event_digest {
                return Err(PinnedDidResolutionError::HistoryUnverifiable(
                    "local did:webvh event digest does not match stored operation".to_owned(),
                ));
            }
            if event.operation.pointer("/parameters/witness").is_some() {
                return Err(PinnedDidResolutionError::HistoryUnverifiable(
                    "local did:webvh witness evidence is unavailable at the resolver boundary"
                        .to_owned(),
                ));
            }
            raw_entries.push(event.operation.clone());
        }
        let history = arkret_identity::verify_did_webvh_v1_chain(did, &raw_entries)
            .map_err(|error| PinnedDidResolutionError::HistoryUnverifiable(error.to_string()))?;
        select_pinned_did_webvh_state(did, &history, version_id, log_head_digest)
    }

    /// Resolve and verify the complete did:webvh history, then return its
    /// current method-native head. This is used before issuing a registration
    /// challenge so an unresolvable or deactivated DID never receives a
    /// challenge that no valid control proof can satisfy.
    pub async fn resolve_current_webvh_state(
        &self,
        did: &DidFullId,
    ) -> Result<PinnedDidDocumentState, PinnedDidResolutionError> {
        if did.method() != "webvh" {
            return Err(PinnedDidResolutionError::UnsupportedMethod);
        }
        let mut local_events = self
            .documents
            .log_events(did.as_str())
            .await
            .map_err(|error| {
                PinnedDidResolutionError::HistoryUnverifiable(format!(
                    "local DID history lookup failed: {error}"
                ))
            })?;
        if local_events.is_empty() {
            return self
                .resolver
                .resolve_current_external_webvh_state(did)
                .await;
        }
        local_events.sort_by_key(|event| event.seq);
        let mut raw_entries = Vec::with_capacity(local_events.len());
        for (index, event) in local_events.iter().enumerate() {
            let expected_seq = index as u64 + 1;
            if event.did != did.as_str() || event.seq != expected_seq {
                return Err(PinnedDidResolutionError::HistoryUnverifiable(
                    "local did:webvh log identity or sequence is inconsistent".to_owned(),
                ));
            }
            let canonical_digest =
                arkret_canonical::canonical_sha256(&event.operation).map_err(|error| {
                    PinnedDidResolutionError::HistoryUnverifiable(format!(
                        "local did:webvh event digest failed: {error}"
                    ))
                })?;
            if canonical_digest != event.event_digest {
                return Err(PinnedDidResolutionError::HistoryUnverifiable(
                    "local did:webvh event digest does not match stored operation".to_owned(),
                ));
            }
            if event.operation.pointer("/parameters/witness").is_some() {
                return Err(PinnedDidResolutionError::HistoryUnverifiable(
                    "local did:webvh witness evidence is unavailable at the resolver boundary"
                        .to_owned(),
                ));
            }
            raw_entries.push(event.operation.clone());
        }
        let history = arkret_identity::verify_did_webvh_v1_chain(did, &raw_entries)
            .map_err(|error| PinnedDidResolutionError::HistoryUnverifiable(error.to_string()))?;
        let head = history.raw_entries.last().ok_or_else(|| {
            PinnedDidResolutionError::HistoryUnverifiable(
                "verified did:webvh history has no head".to_owned(),
            )
        })?;
        let digest = Hash::new(arkret_canonical::canonical_sha256(head).map_err(|error| {
            PinnedDidResolutionError::HistoryUnverifiable(format!(
                "verified did:webvh head digest failed: {error}"
            ))
        })?)
        .map_err(|error| PinnedDidResolutionError::HistoryUnverifiable(error.to_string()))?;
        select_pinned_did_webvh_state(did, &history, &history.head_version_id, &digest)
    }

    pub fn cache_resolved_document_state(
        &self,
        document: DidDocumentState,
    ) -> Result<arkret_identity::DidDocument, String> {
        self.resolver.cache_document_state(document)
    }

    pub async fn document(&self, did: &str) -> ServiceResult<Option<DidDocumentState>> {
        self.documents.document(did).await
    }

    pub async fn embedded_document(
        &self,
        local_id: &str,
    ) -> ServiceResult<Option<DidDocumentState>> {
        self.documents.embedded_document(local_id).await
    }

    pub async fn log_events(&self, did: &str) -> ServiceResult<Vec<DidLogEvent>> {
        self.documents.log_events(did).await
    }

    pub async fn store_document(&self, document: DidDocumentState) -> ServiceResult<()> {
        self.documents.store_document(document).await
    }

    pub async fn append_log_event(&self, event: DidLogEvent) -> ServiceResult<()> {
        self.documents.append_log_event(event).await
    }

    pub async fn service_registration(
        &self,
        key: &ServiceRegistrationKey,
    ) -> ServiceResult<Option<ServiceRegistrationOutcome>> {
        self.documents.service_registration(key).await
    }

    pub async fn commit_service_registration(
        &self,
        key: ServiceRegistrationKey,
        outcome: ServiceRegistrationOutcome,
        document: DidDocumentState,
        event: DidLogEvent,
    ) -> ServiceResult<ServiceRegistrationCommitResult> {
        self.documents
            .commit_service_registration(key, outcome, document, event)
            .await
    }

    pub async fn commit_log_operation(
        &self,
        expected_current_head: Option<String>,
        document: DidDocumentState,
        event: DidLogEvent,
    ) -> ServiceResult<DidLogCommitResult> {
        self.documents
            .commit_log_operation(expected_current_head, document, event)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recovery_policy_basis() -> LeaseBasisRef {
        LeaseBasisRef::Seal(
            arkret_identifiers::SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).unwrap(),
        )
    }

    const ACTIVE_BINDING_AGENT_ID: &str = "ak:did_core:web:agent.example";
    const ACTIVE_BINDING_VERIFICATION_METHOD: &str = "did:web:agent.example#key-1";
    const ACTIVE_BINDING_EVENT_ID: &str = "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";

    fn active_signing_key_binding()
    -> arkret_models_identity::agent_signer_evidence::AgentSigningKeyBinding {
        let mut binding: arkret_models_identity::agent_signer_evidence::AgentSigningKeyBinding =
            serde_json::from_value(serde_json::json!({
                "schema": "ak.schema.agent_signing_key_binding.v1",
                "agent_id": ACTIVE_BINDING_AGENT_ID,
                "agent_key_id": "runtime-1",
                "verification_method": ACTIVE_BINDING_VERIFICATION_METHOD,
                "public_key": {
                    "kty": "OKP",
                    "algorithm": "Ed25519",
                    "key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                },
                "public_key_digest": format!("sha256:{}", "00".repeat(32)),
                "agent_key_authorize_event_id": ACTIVE_BINDING_EVENT_ID,
                "issued_at": "2026-07-27T00:00:00.000Z",
                "controller_id": "ak:did_core:web:alice.example",
                "controller_proof": {
                    "kind": "controller_signature",
                    "verification_method": "did:web:alice.example#key-1",
                    "jws": "proof"
                }
            }))
            .expect("valid signing-key binding fixture");
        binding.core.public_key_digest =
            arkret_signatures::agent_evidence::agent_signing_public_key_digest(&binding.public_key)
                .expect("authorization-domain digest");
        binding
    }

    fn active_agent_pairing_state(
        binding: arkret_models_identity::agent_signer_evidence::AgentSigningKeyBinding,
        authorized_public_key_digest: String,
    ) -> AgentPairingState {
        let mut record = AgentPairingState::new(
            ACTIVE_BINDING_AGENT_ID.to_owned(),
            "ak:did_core:web:alice.example".to_owned(),
            "ak:realm:personal".to_owned(),
            DidUrl::new("did:web:alice.example#key-1".to_owned()).unwrap(),
            AgentLifecycleState::Active,
            Utc::now(),
        );
        let pairing_request_id = OpaqueLocalId::new("pairing-1").unwrap();
        record.pairing_request_id = Some(pairing_request_id.clone());
        record.paired_pairing_request_id = Some(pairing_request_id);
        record.authorized_event_ref = Some(ACTIVE_BINDING_EVENT_ID.to_owned());
        record.authorized_verification_method = Some(ACTIVE_BINDING_VERIFICATION_METHOD.to_owned());
        record.authorized_public_key_digest = Some(authorized_public_key_digest);
        record.authorized_signing_key_binding = Some(binding);
        record
    }

    /// `authorized_public_key_digest` is the public authorization domain (the
    /// raw Ed25519 key hash the authorize Event binds), not the private
    /// pairing-request JWK domain. Reading back an activated Agent must
    /// succeed instead of failing the consistency gate.
    #[test]
    fn active_runtime_binding_reads_back_with_authorization_domain_digest() {
        let binding = active_signing_key_binding();
        let record =
            active_agent_pairing_state(binding.clone(), binding.public_key_digest.to_string());
        let bindings = record
            .runtime_bindings()
            .expect("active runtime binding is readable");
        let active = bindings
            .active_binding
            .expect("active binding is reconstructed");
        assert_eq!(active.public_key_digest, binding.public_key_digest);
        assert!(bindings.open_handle.is_none());
    }

    #[test]
    fn active_runtime_binding_rejects_runtime_request_domain_digest() {
        let binding = active_signing_key_binding();
        let runtime_request_digest =
            arkret_signatures::agent_evidence::agent_signing_public_key_runtime_request_digest(
                &binding.verification_method,
                &binding.public_key,
            )
            .expect("runtime-request-domain digest");
        assert_ne!(runtime_request_digest, binding.public_key_digest);
        let record = active_agent_pairing_state(binding, runtime_request_digest.to_string());
        assert!(record.runtime_bindings().is_err());
    }

    struct StaticAccount;

    struct NoDevices;

    struct NoAgents;

    struct NoSidecars;

    struct StaticDidDocuments;

    struct NoDidResolver;

    impl arkret_identity::DidResolver for NoDidResolver {
        fn supports(&self, _did: &DidFullId) -> bool {
            false
        }

        fn resolve_did(
            &self,
            _did: &DidFullId,
        ) -> arkret_identity::Result<arkret_identity::ResolvedDid> {
            Err(arkret_identity::IdentityError::Protocol(
                "DID resolver is unused in this test".to_owned(),
            ))
        }
    }

    #[async_trait]
    impl DidResolverPort for NoDidResolver {
        async fn resolve_did_async(
            &self,
            _did: &DidFullId,
        ) -> Result<arkret_identity::DidDocument, String> {
            Err("DID resolver is unused in this test".to_owned())
        }

        async fn resolve_current_external_webvh_state(
            &self,
            _did: &DidFullId,
        ) -> Result<PinnedDidDocumentState, PinnedDidResolutionError> {
            Err(PinnedDidResolutionError::HistoryUnavailable)
        }

        async fn resolve_external_pinned_webvh_state(
            &self,
            _did: &DidFullId,
            _version_id: &str,
            _log_head_digest: &Hash,
        ) -> Result<PinnedDidDocumentState, PinnedDidResolutionError> {
            Err(PinnedDidResolutionError::HistoryUnavailable)
        }

        fn cache_document_state(
            &self,
            _document: DidDocumentState,
        ) -> Result<arkret_identity::DidDocument, String> {
            Err("DID resolver is unused in this test".to_owned())
        }
    }

    struct AcceptPairing;

    struct CurrentRecoveryPolicy;

    fn pinned_history_fixture() -> (DidFullId, arkret_identity::VerifiedDidWebvhLog, Hash) {
        let did = DidFullId::new("did:webvh:zFixture:organization.example".to_owned()).unwrap();
        let first_state = serde_json::json!({
            "id": did,
            "verificationMethod": [{
                "id": format!("{did}#control-1"),
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": "z6MkrJVnaZkeFzdQyHL9T5yCDonTuB9R2cZWLMgLMN8GX4gu"
            }]
        });
        let second_state = serde_json::json!({
            "id": did,
            "verificationMethod": [{
                "id": format!("{did}#control-2"),
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": "z6MkrJVnaZkeFzdQyHL9T5yCDonTuB9R2cZWLMgLMN8GX4gu"
            }]
        });
        let first_raw = serde_json::json!({
            "versionId": "1-first",
            "versionTime": "2026-07-01T00:00:00Z",
            "parameters": {
                "method": "did:webvh:1.0",
                "scid": "zFixture",
                "updateKeys": ["z6MkrJVnaZkeFzdQyHL9T5yCDonTuB9R2cZWLMgLMN8GX4gu"]
            },
            "state": first_state,
            "proof": []
        });
        let second_raw = serde_json::json!({
            "versionId": "2-second",
            "versionTime": "2026-07-02T00:00:00Z",
            "parameters": {
                "method": "did:webvh:1.0",
                "scid": "zFixture",
                "updateKeys": ["z6MkrJVnaZkeFzdQyHL9T5yCDonTuB9R2cZWLMgLMN8GX4gu"]
            },
            "state": second_state,
            "proof": []
        });
        let first_digest =
            Hash::new(arkret_canonical::canonical_sha256(&first_raw).unwrap()).unwrap();
        let history = arkret_identity::VerifiedDidWebvhLog {
            raw_entries: vec![first_raw, second_raw],
            entries: vec![
                arkret_identity::DidWebvhLogEntry {
                    version_id: "1-first".to_owned(),
                    version_time: "2026-07-01T00:00:00Z".parse().unwrap(),
                    parameters: serde_json::json!({
                        "method": "did:webvh:1.0",
                        "scid": "zFixture",
                        "updateKeys": ["z6MkrJVnaZkeFzdQyHL9T5yCDonTuB9R2cZWLMgLMN8GX4gu"]
                    }),
                    state: first_state,
                    proof: Vec::new(),
                },
                arkret_identity::DidWebvhLogEntry {
                    version_id: "2-second".to_owned(),
                    version_time: "2026-07-02T00:00:00Z".parse().unwrap(),
                    parameters: serde_json::json!({
                        "method": "did:webvh:1.0",
                        "scid": "zFixture",
                        "updateKeys": ["z6MkrJVnaZkeFzdQyHL9T5yCDonTuB9R2cZWLMgLMN8GX4gu"]
                    }),
                    state: second_state,
                    proof: Vec::new(),
                },
            ],
            head_version_id: "2-second".to_owned(),
            head_state: serde_json::Value::Null,
            active_update_keys: vec!["z6MkrJVnaZkeFzdQyHL9T5yCDonTuB9R2cZWLMgLMN8GX4gu".to_owned()],
        };
        (did, history, first_digest)
    }

    #[test]
    fn pinned_webvh_selection_returns_exact_historical_state_and_rotation_status() {
        let (did, history, first_digest) = pinned_history_fixture();
        let selected =
            select_pinned_did_webvh_state(&did, &history, "1-first", &first_digest).unwrap();
        assert_eq!(selected.version_id, "1-first");
        assert_eq!(selected.current_version_id, "2-second");
        assert_eq!(selected.status, PinnedDidVersionStatus::Rotated);
        assert_eq!(
            selected.document["verificationMethod"][0]["id"],
            format!("{did}#control-1")
        );
    }

    #[test]
    fn pinned_webvh_selection_rejects_digest_substitution() {
        let (did, history, _) = pinned_history_fixture();
        let wrong_digest = Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap();
        assert_eq!(
            select_pinned_did_webvh_state(&did, &history, "1-first", &wrong_digest),
            Err(PinnedDidResolutionError::DigestMismatch)
        );
    }

    #[test]
    fn pinned_webvh_selection_surfaces_terminal_deactivation() {
        let (did, mut history, first_digest) = pinned_history_fixture();
        history.entries[1]
            .parameters
            .as_object_mut()
            .unwrap()
            .insert("deactivated".to_owned(), Value::Bool(true));
        let selected =
            select_pinned_did_webvh_state(&did, &history, "1-first", &first_digest).unwrap();
        assert_eq!(selected.status, PinnedDidVersionStatus::Deactivated);
    }

    #[async_trait]
    impl SidecarPort for NoSidecars {
        async fn ensure_sidecar(
            &self,
            _sidecar: AgentSidecarState,
        ) -> ServiceResult<AgentSidecarState> {
            panic!("unused test port")
        }
        async fn sidecar(&self, _sidecar_id: &str) -> ServiceResult<Option<AgentSidecarState>> {
            Ok(None)
        }
        async fn sidecar_for_realm_controller(
            &self,
            _realm_id: &str,
            _controller_id: &str,
        ) -> ServiceResult<Option<AgentSidecarState>> {
            Ok(None)
        }
        async fn sidecars_for_controller(
            &self,
            _controller_id: &str,
            _realm_id: Option<&str>,
        ) -> ServiceResult<Vec<AgentSidecarState>> {
            Ok(Vec::new())
        }
        async fn ensure_context(
            &self,
            _context: AgentSidecarContextState,
        ) -> ServiceResult<AgentSidecarContextState> {
            panic!("unused test port")
        }
        async fn context(
            &self,
            _sidecar_id: &str,
            _digest: &str,
        ) -> ServiceResult<Option<AgentSidecarContextState>> {
            Ok(None)
        }
    }

    #[async_trait]
    impl AccountLookupPort for StaticAccount {
        async fn find_account_by_actor(
            &self,
            actor_id: &str,
        ) -> ServiceResult<Option<AccountIdentity>> {
            Ok(
                (actor_id == "did:web:alice.example").then(|| AccountIdentity {
                    account_id: "ak:account:alice".to_owned(),
                }),
            )
        }

        async fn register_account(&self, _command: RegisterAccountCommand) -> ServiceResult<()> {
            Ok(())
        }

        async fn account(&self, _actor_id: &str) -> ServiceResult<Option<AccountProfileState>> {
            Ok(None)
        }

        async fn accounts(&self) -> ServiceResult<Vec<AccountProfileState>> {
            Ok(Vec::new())
        }

        async fn save_account(&self, _account: AccountProfileState) -> ServiceResult<()> {
            Ok(())
        }

        async fn delete_account(&self, _actor_id: &str) -> ServiceResult<()> {
            Ok(())
        }

        async fn account_localparts(
            &self,
            _actor_id: &str,
        ) -> ServiceResult<Vec<AccountLocalpartState>> {
            Ok(Vec::new())
        }

        async fn localpart_owner(
            &self,
            _localpart: &str,
        ) -> ServiceResult<Option<AccountLocalpartState>> {
            Ok(None)
        }

        async fn add_localpart(
            &self,
            _actor_id: &str,
            _localpart: &str,
            _primary: bool,
        ) -> ServiceResult<AccountLocalpartState> {
            unreachable!()
        }

        async fn set_primary_localpart(
            &self,
            _actor_id: &str,
            _localpart: &str,
        ) -> ServiceResult<AccountLocalpartState> {
            unreachable!()
        }

        async fn remove_localpart(&self, _actor_id: &str, _localpart: &str) -> ServiceResult<()> {
            Ok(())
        }

        async fn clear_localparts(&self, _actor_id: &str) -> ServiceResult<()> {
            Ok(())
        }

        async fn record_handle_release(
            &self,
            _localpart: &str,
            _released_at: DateTime<Utc>,
        ) -> ServiceResult<()> {
            Ok(())
        }

        async fn save_account_lifecycle(
            &self,
            _actor_id: &str,
            _lifecycle: AccountLifecycleState,
        ) -> ServiceResult<()> {
            Ok(())
        }

        async fn delete_account_lifecycle(&self, _actor_id: &str) -> ServiceResult<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl DeviceDirectoryPort for NoDevices {
        async fn list_active_device_actors(&self) -> ServiceResult<Vec<String>> {
            Ok(Vec::new())
        }

        async fn devices(&self) -> ServiceResult<Vec<DeviceIdentity>> {
            Ok(Vec::new())
        }

        async fn find_device(
            &self,
            _actor_id: &str,
            _device_id: &str,
        ) -> ServiceResult<Option<DeviceIdentity>> {
            Ok(None)
        }

        async fn save_device(&self, _command: SaveDeviceCommand) -> ServiceResult<()> {
            Ok(())
        }

        async fn save_device_if_absent(&self, _device: DeviceIdentity) -> ServiceResult<bool> {
            Ok(true)
        }

        async fn devices_for_actor(&self, _actor_id: &str) -> ServiceResult<Vec<DeviceIdentity>> {
            Ok(Vec::new())
        }
    }

    #[async_trait]
    impl AgentDirectoryPort for NoAgents {
        async fn find_agent_controller(
            &self,
            _agent_id: &str,
        ) -> ServiceResult<Option<AgentController>> {
            Ok(None)
        }
    }

    #[async_trait]
    impl DidDocumentPort for StaticDidDocuments {
        async fn document(&self, did: &str) -> ServiceResult<Option<DidDocumentState>> {
            let now = Utc::now();
            Ok((did == "did:web:alice.example").then(|| DidDocumentState {
                did: did.to_owned(),
                did_document: serde_json::json!({"id": did}),
                key_log_head: None,
                seq: 1,
                method_evidence: Value::Null,
                fetched_at: now,
                expires_at: now,
                updated_at: now,
            }))
        }

        async fn embedded_document(
            &self,
            _local_id: &str,
        ) -> ServiceResult<Option<DidDocumentState>> {
            Ok(None)
        }

        async fn log_events(&self, _did: &str) -> ServiceResult<Vec<DidLogEvent>> {
            Ok(Vec::new())
        }

        async fn store_document(&self, _document: DidDocumentState) -> ServiceResult<()> {
            Ok(())
        }

        async fn append_log_event(&self, _event: DidLogEvent) -> ServiceResult<()> {
            Ok(())
        }

        async fn service_registration(
            &self,
            _key: &ServiceRegistrationKey,
        ) -> ServiceResult<Option<ServiceRegistrationOutcome>> {
            Ok(None)
        }

        async fn commit_service_registration(
            &self,
            _key: ServiceRegistrationKey,
            _outcome: ServiceRegistrationOutcome,
            _document: DidDocumentState,
            _event: DidLogEvent,
        ) -> ServiceResult<ServiceRegistrationCommitResult> {
            Ok(ServiceRegistrationCommitResult::Conflict)
        }

        async fn commit_log_operation(
            &self,
            _expected_current_head: Option<String>,
            _document: DidDocumentState,
            _event: DidLogEvent,
        ) -> ServiceResult<DidLogCommitResult> {
            Ok(DidLogCommitResult::Conflict)
        }
    }

    #[async_trait]
    impl AgentPairingPort for AcceptPairing {
        async fn pairing_record(
            &self,
            _pairing_request_id: &str,
        ) -> ServiceResult<Option<AgentPairingState>> {
            Ok(None)
        }

        async fn agent(&self, _agent_id: &str) -> ServiceResult<Option<AgentPairingState>> {
            Ok(None)
        }

        async fn agents_for_controller(
            &self,
            _controller_id: &str,
        ) -> ServiceResult<Vec<AgentPairingState>> {
            Ok(Vec::new())
        }

        async fn save_agent(&self, _agent: AgentPairingState) -> ServiceResult<()> {
            Ok(())
        }

        async fn store_runtime_approval(
            &self,
            _command: &StoreAgentRuntimeApprovalCommand,
        ) -> ServiceResult<Option<AgentPairingState>> {
            Ok(None)
        }

        async fn activate_runtime_if_current(
            &self,
            command: &ActivateAgentRuntimeCommand,
        ) -> ServiceResult<bool> {
            Ok(command.pairing_request_id.as_str() == "pairing-1")
        }

        async fn record_pairing_commit_intent(
            &self,
            _command: &RecordAgentPairingCommitIntentCommand,
        ) -> ServiceResult<Option<AgentPairingState>> {
            Ok(None)
        }

        async fn clear_approval_notification_if_current(
            &self,
            _agent_id: &str,
            _approval_request_id: &str,
        ) -> ServiceResult<bool> {
            Ok(true)
        }

        async fn issue_provisioning_abandonment_challenge(
            &self,
            _command: &soland_storage::IssueAgentProvisioningAbandonmentChallenge,
        ) -> ServiceResult<soland_storage::AgentProvisioningAbandonmentWriteOutcome> {
            Ok(soland_storage::AgentProvisioningAbandonmentWriteOutcome::NotFound)
        }

        async fn confirm_provisioning_abandonment(
            &self,
            _command: &soland_storage::ConfirmAgentProvisioningAbandonment,
        ) -> ServiceResult<soland_storage::AgentProvisioningAbandonmentWriteOutcome> {
            Ok(soland_storage::AgentProvisioningAbandonmentWriteOutcome::NotFound)
        }

        async fn enqueue_runtime_message_if_current(
            &self,
            _command: &EnqueueAgentRuntimeMessageCommand,
        ) -> ServiceResult<AgentRuntimeEnqueueResult> {
            Ok(soland_storage::AgentRuntimeEnqueueOutcome::SnapshotConflict)
        }
    }

    #[async_trait]
    impl RecoveryPolicyPort for CurrentRecoveryPolicy {
        async fn active_policy(
            &self,
            principal_id: &str,
        ) -> ServiceResult<Option<RecoveryPolicyState>> {
            Ok(Some(RecoveryPolicyState {
                policy_id: "ak:policy:current".to_owned(),
                principal_id: principal_id.to_owned(),
                version: 2,
                acceptance_basis: recovery_policy_basis(),
                trust_domain: "ak:trust_domain:personal".to_owned(),
                allowed_proof_kinds: vec!["principal_signing".to_owned()],
                supersedes: Some("ak:policy:genesis".to_owned()),
                expires_at: None,
                issued_at: Utc::now(),
                raw_payload: Value::Null,
                accepted_at: Utc::now(),
                verification_method: "did:web:alice.example#key-1".to_owned(),
            }))
        }

        async fn policy_history(
            &self,
            _principal_id: &str,
        ) -> ServiceResult<Vec<RecoveryPolicyState>> {
            Ok(Vec::new())
        }

        async fn insert_policy(&self, _policy: RecoveryPolicyState) -> ServiceResult<()> {
            panic!("a non-monotonic policy must not reach persistence")
        }
    }

    #[tokio::test]
    async fn account_lookup_returns_application_owned_result() {
        let service = IdentityService::new(
            Arc::new(StaticAccount),
            Arc::new(NoDevices),
            Arc::new(NoAgents),
        );
        let account = service
            .find_account_by_actor(FindAccountByActorQuery {
                actor_id: "did:web:alice.example".to_owned(),
            })
            .await
            .expect("lookup account")
            .expect("account exists");
        assert_eq!(account.account_id, "ak:account:alice");
    }

    #[tokio::test]
    async fn did_lookup_is_independent_from_http_and_app_state() {
        let service = DidService::new(Arc::new(StaticDidDocuments), Arc::new(NoDidResolver));
        let document = service
            .document("did:web:alice.example")
            .await
            .expect("lookup DID")
            .expect("DID exists");
        assert_eq!(
            document.did_document,
            serde_json::json!({"id": document.did})
        );
    }

    #[tokio::test]
    async fn pairing_activation_is_one_atomic_port_call() {
        let service = AgentPairingService::new(Arc::new(AcceptPairing), Arc::new(NoSidecars));
        let command = ActivateAgentRuntimeCommand {
            agent_id: "ak:did_core:web:agent.example".to_owned(),
            approval_request_id: OpaqueLocalId::new("approval-1").unwrap(),
            runtime_key_binding_digest: "sha256:binding".to_owned(),
            pairing_request_id: OpaqueLocalId::new("pairing-1").unwrap(),
            paired_request_digest: "sha256:request".to_owned(),
            authorized_event_ref: "ak:event:1".to_owned(),
            authorized_verification_method: "did:web:agent.example#key-1".to_owned(),
            authorized_public_key_digest: "sha256:key".to_owned(),
            authorized_signing_key_binding: serde_json::from_value(serde_json::json!({
                "schema": "ak.schema.agent_signing_key_binding.v1",
                "agent_id": "ak:did_core:web:agent.example",
                "agent_key_id": "runtime-1",
                "verification_method": "did:web:agent.example#key-1",
                "public_key": {
                    "kty": "OKP",
                    "algorithm": "Ed25519",
                    "key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                },
                "public_key_digest": format!("sha256:{}", "00".repeat(32)),
                "agent_key_authorize_event_id":
                    "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                "issued_at": "2026-07-27T00:00:00.000Z",
                "controller_id": "ak:did_core:web:alice.example",
                "controller_proof": {
                    "kind": "controller_signature",
                    "verification_method": "did:web:alice.example#key-1",
                    "jws": "proof"
                }
            }))
            .expect("valid signing-key binding fixture"),
            authorized_at: Utc::now(),
        };
        assert!(
            service
                .activate_runtime(&command)
                .await
                .expect("activate runtime")
        );
    }

    #[tokio::test]
    async fn recovery_policy_monotonicity_is_enforced_in_application() {
        let service = RecoveryPolicyService::new(Arc::new(CurrentRecoveryPolicy));
        let result = service
            .publish_policy(PublishRecoveryPolicyCommand {
                policy: RecoveryPolicyState {
                    policy_id: "ak:policy:stale".to_owned(),
                    principal_id: "did:web:alice.example".to_owned(),
                    version: 2,
                    acceptance_basis: recovery_policy_basis(),
                    trust_domain: "ak:trust_domain:personal".to_owned(),
                    allowed_proof_kinds: vec!["principal_signing".to_owned()],
                    supersedes: Some("ak:policy:current".to_owned()),
                    expires_at: None,
                    issued_at: Utc::now(),
                    raw_payload: Value::Null,
                    accepted_at: Utc::now(),
                    verification_method: "did:web:alice.example#key-1".to_owned(),
                },
            })
            .await
            .expect("evaluate policy");
        assert!(matches!(
            result,
            PublishRecoveryPolicyResult::VersionNotMonotonic {
                actual: 2,
                current: 2
            }
        ));
    }
}
