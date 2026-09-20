use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use arkret_identifiers::{DidCoreId, RealmId};
use arkret_models_collaboration::events_payloads::ContentBlock;
use arkret_models_collaboration::events_payloads::agent::{
    AgentProvisionAccountabilityScope, AgentProvisionPayload,
};
use arkret_models_collaboration::governance::accountability::{
    AccountabilityGrantPayload, AccountabilityScopeKind,
};
use arkret_models_collaboration::objects::read_receipts::ReadCursorCausalRelation;
use arkret_models_crypto::MlsGovernanceBindingPayload;
use arkret_wire::ScopeRef;
use chrono::{DateTime, Utc};
use serde_json::Value;
pub use soland_storage::PublicationEvidenceRecord;
use soland_storage::RealmEventStats;

use crate::ServiceResult;

#[derive(Clone, Debug, Default)]
pub struct RealmDirectoryQuery {
    pub text: Option<String>,
    pub tags: BTreeSet<String>,
    pub members: BTreeSet<DidCoreId>,
    pub public_only: bool,
    pub limit: Option<usize>,
}

#[derive(Clone, Debug)]
pub struct ActiveAgentAccountabilityQuery {
    pub accountability_event_id: String,
    pub controller_account_id: arkret_wire::AccountId,
    pub agent_account_id: arkret_wire::AccountId,
    pub accepted_at: DateTime<Utc>,
}

pub use soland_storage::{
    CircleMemberProjectionRecord, CircleProjectionRecord, RealmOrganizationStatementRecord,
    SpaceContainerProjectionRecord, StrandProjectionRecord, StrandWatchProjectionRecord,
};

#[derive(Clone, Debug, PartialEq)]
pub struct MorphProjectionRecord {
    pub morph_id: String,
    pub realm_id: String,
    pub scope_circle_id: Option<String>,
    pub morph_kind: String,
    pub title: Option<String>,
    pub fields: BTreeMap<String, Value>,
    pub schema_refs: Vec<String>,
    pub facets: BTreeMap<String, BTreeMap<String, Value>>,
    pub versions: Vec<soland_domain::reducer::DocumentVersionProjection>,
    /// Canonical content slot; exactly one of the two is present on an active
    /// object and both are absent once `state=redacted` (common-fields.md 5.2).
    /// Typed as the SDK [`ContentBlock`], matching
    /// `arkret_models_collaboration::objects::profiles::Morph`.
    pub content: Option<ContentBlock>,
    pub encrypted_content: Option<serde_json::Value>,
    pub state: String,
    pub state_changed_at: Option<DateTime<Utc>>,
    /// Wire spelling of the business-progression stage (`common-fields.md`
    /// §5.3), absent when the Morph carries no stage.
    pub stage: Option<String>,
    /// Reducer-derived timestamp of the last real stage transition.
    pub stage_changed_at: Option<DateTime<Utc>>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub updated_by: Option<String>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmDirectoryEntry {
    pub realm_id: RealmId,
    pub title: String,
    pub description: Option<String>,
    pub tags: BTreeSet<String>,
    pub members: BTreeSet<DidCoreId>,
    pub public: bool,
    pub category: Option<String>,
    pub realm_class: Option<String>,
    pub default_join_rule: Option<String>,
    pub as_of: DateTime<Utc>,
    pub source_refs: Vec<String>,
    pub policy_revision: String,
    /// Caller-visible Directory data exists only after a verified direct
    /// publication from the current governance Station. Realm reducer state,
    /// membership, source references, and join policy never populate it.
    pub public_metadata: Option<PublicRealmMetadataRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicRealmMetadataRecord {
    pub display_name: String,
    pub summary: Option<String>,
    pub public_locator: Option<String>,
    pub avatar_blob_ref: Option<arkret_wire::BlobRef>,
    pub indexed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Where a directory entry's `source_refs` comes from.
///
/// `source_refs` exists so a consumer can go back to the truth source and verify
/// the entry itself (`discovery-directory.md` §7.3 invariant 3). The constructor
/// used to default it to a freshly minted `ak:event:` uuid, which made that
/// impossible in the exact way the field was meant to prevent: the id resolves to
/// nothing, and it *looks* verifiable, so a consumer spends a lookup finding out.
/// Worse, every caller that had a real Event id available inherited the forged one
/// unless it remembered to overwrite the field — and only one of eleven did.
///
/// Two constructors would have let a caller pick the convenient one. An enum makes
/// "this entry has no Event behind it" a thing you have to say out loud.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DirectoryProvenance {
    /// Derived from an accepted Event; carries that Event's id.
    AcceptedEvent(String),
    /// Server-local synthesis with no Event behind it. `source_refs` is omitted
    /// on the wire; `policy_revision = "local"` marks the entry.
    LocalOnly,
}

impl DirectoryProvenance {
    fn source_refs(self) -> Vec<String> {
        match self {
            Self::AcceptedEvent(event_id) => vec![event_id],
            Self::LocalOnly => Vec::new(),
        }
    }
}

impl RealmDirectoryEntry {
    pub fn new(
        realm_id: RealmId,
        title: impl Into<String>,
        provenance: DirectoryProvenance,
    ) -> Self {
        Self {
            realm_id,
            title: title.into(),
            description: None,
            tags: BTreeSet::new(),
            members: BTreeSet::new(),
            public: false,
            category: None,
            realm_class: None,
            default_join_rule: None,
            as_of: DateTime::from_timestamp_millis(Utc::now().timestamp_millis())
                .expect("current time is representable at millisecond precision"),
            source_refs: provenance.source_refs(),
            policy_revision: "local".to_owned(),
            public_metadata: None,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct RealmDirectoryIndex {
    entries: BTreeMap<RealmId, RealmDirectoryEntry>,
}

impl RealmDirectoryIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn upsert(&mut self, entry: RealmDirectoryEntry) {
        self.entries.insert(entry.realm_id.clone(), entry);
    }

    pub fn get(&self, realm_id: &RealmId) -> Option<&RealmDirectoryEntry> {
        self.entries.get(realm_id)
    }

    pub fn get_mut(&mut self, realm_id: &RealmId) -> Option<&mut RealmDirectoryEntry> {
        self.entries.get_mut(realm_id)
    }

    pub fn entries_iter(&self) -> impl Iterator<Item = (&RealmId, &RealmDirectoryEntry)> {
        self.entries.iter()
    }

    pub fn search(&self, query: RealmDirectoryQuery) -> Vec<&RealmDirectoryEntry> {
        let mut scored =
            self.entries
                .values()
                .filter(|entry| !query.public_only || entry.public)
                .filter(|entry| {
                    query.text.as_ref().is_none_or(|text| {
                        realm_directory_text(entry).contains(&text.to_lowercase())
                    })
                })
                .filter(|entry| query.tags.iter().all(|tag| entry.tags.contains(tag)))
                .filter(|entry| {
                    query
                        .members
                        .iter()
                        .all(|member| entry.members.contains(member))
                })
                .map(|entry| (realm_directory_score(entry, &query), entry))
                .collect::<Vec<_>>();
        scored.sort_by(|(left_score, left), (right_score, right)| {
            right_score
                .cmp(left_score)
                .then_with(|| left.title.cmp(&right.title))
        });
        let mut results = scored
            .into_iter()
            .map(|(_, entry)| entry)
            .collect::<Vec<_>>();
        if let Some(limit) = query.limit {
            results.truncate(limit);
        }
        results
    }
}

#[derive(Clone)]
pub struct RealmDirectoryService {
    index: Arc<parking_lot::Mutex<RealmDirectoryIndex>>,
}

impl RealmDirectoryService {
    pub fn new(index: RealmDirectoryIndex) -> Self {
        Self {
            index: Arc::new(parking_lot::Mutex::new(index)),
        }
    }

    pub fn snapshot(&self) -> RealmDirectoryIndex {
        self.index.lock().clone()
    }

    pub fn entry(&self, realm_id: &RealmId) -> Option<RealmDirectoryEntry> {
        self.index.lock().get(realm_id).cloned()
    }

    pub fn upsert(&self, entry: RealmDirectoryEntry) {
        self.index.lock().upsert(entry);
    }

    pub fn update_entry<R>(
        &self,
        realm_id: &RealmId,
        update: impl FnOnce(&mut RealmDirectoryEntry) -> R,
    ) -> Option<R> {
        self.index.lock().get_mut(realm_id).map(update)
    }

    pub fn add_member(&self, realm_id: &RealmId, member: DidCoreId) -> bool {
        self.update_entry(realm_id, |entry| entry.members.insert(member))
            .unwrap_or(false)
    }

    pub fn remove_member_from_all(&self, member: &DidCoreId) -> usize {
        let mut index = self.index.lock();
        let mut removed = 0;
        for entry in index.entries.values_mut() {
            if entry.members.remove(member) {
                removed += 1;
            }
        }
        removed
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn test_index(&self) -> &Arc<parking_lot::Mutex<RealmDirectoryIndex>> {
        &self.index
    }
}

fn realm_directory_text(entry: &RealmDirectoryEntry) -> String {
    format!(
        "{} {} {}",
        entry.title,
        entry.description.as_deref().unwrap_or_default(),
        entry.tags.iter().cloned().collect::<Vec<_>>().join(" ")
    )
    .to_lowercase()
}

fn realm_directory_score(entry: &RealmDirectoryEntry, query: &RealmDirectoryQuery) -> usize {
    let mut score = 0;
    if let Some(text) = &query.text {
        let text = text.to_lowercase();
        if entry.title.to_lowercase().contains(&text) {
            score += 10;
        }
        if entry
            .description
            .as_deref()
            .unwrap_or_default()
            .to_lowercase()
            .contains(&text)
        {
            score += 4;
        }
    }
    score += query
        .tags
        .iter()
        .filter(|tag| entry.tags.contains(*tag))
        .count()
        * 3;
    score += query
        .members
        .iter()
        .filter(|member| entry.members.contains(*member))
        .count()
        * 2;
    score
}

pub use soland_storage::CanonicalEventRecord as AcceptedEvent;

/// Locate the replacement `ak.device.authorize` that belongs to one accepted
/// B-model re-anchor.
///
/// The pairing lives in the authorize envelope: its `prev_refs` is exactly the
/// re-anchor id (`key-management.md` §5.0.7). The re-anchor payload commits
/// only to the authorize *payload* digest, because the authorize envelope
/// already names the re-anchor and every `event_id` derives from its own
/// signed content — an id or envelope-digest binding would make the two Events
/// preimages of each other.
pub fn paired_replacement_authorize<'a>(
    reanchor: &AcceptedEvent,
    records: impl IntoIterator<Item = &'a AcceptedEvent>,
) -> Option<&'a AcceptedEvent> {
    records.into_iter().find(|candidate| {
        arkret_wire::EventKind::DeviceAuthorize == candidate.kind
            && candidate.actor_id == reanchor.actor_id
            && candidate
                .envelope
                .pointer("/prev_refs")
                .and_then(Value::as_array)
                .is_some_and(|refs| {
                    refs.len() == 1 && refs[0].as_str() == Some(reanchor.event_id.as_str())
                })
    })
}

/// Recompute the value a B-model re-anchor commits to.
///
/// The digest suite comes from the authorize envelope digest so the payload
/// commitment and the envelope commitment always speak the same Realm live
/// suite; inferring it from the payload would let the producer choose it.
pub fn replacement_authorize_payload_digest(
    authorize_envelope: &Value,
    authorize_envelope_digest: &str,
) -> Result<arkret_identifiers::Hash, String> {
    let suite = authorize_envelope_digest
        .split_once(':')
        .map(|(suite, _)| suite)
        .ok_or_else(|| "authorize envelope digest carries no suite prefix".to_owned())?;
    let suite = arkret_canonical::digest_suite(suite)
        .map_err(|_| format!("authorize envelope digest suite {suite} is not supported"))?;
    let payload = authorize_envelope
        .get("payload")
        .ok_or_else(|| "authorize envelope carries no payload".to_owned())?;
    arkret_models_collaboration::events_payloads::device_identity::device_authorize_payload_digest(
        payload, suite,
    )
    .map_err(|error| format!("replacement authorize payload digest failed: {error}"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CausalReachability {
    Reachable,
    CompleteUnreachable,
    Incomplete,
}

/// Determine the Decision 0017 causal relation between two read-cursor
/// position Events from the receiver's canonical Event closure.
///
/// `Concurrent` is returned only when both reverse reachability walks are
/// complete. Any missing Event, digest edge, explicit `after` reference, or
/// materialized message reference keeps the relation `Undecidable`.
pub fn read_cursor_causal_relation(
    records: &[AcceptedEvent],
    current_event_id: &str,
    candidate_event_id: &str,
) -> ReadCursorCausalRelation {
    if current_event_id == candidate_event_id {
        return ReadCursorCausalRelation::Concurrent;
    }
    let graph = CanonicalCausalGraph::new(records);
    let candidate_to_current = graph.reaches(candidate_event_id, current_event_id);
    let current_to_candidate = graph.reaches(current_event_id, candidate_event_id);
    match (candidate_to_current, current_to_candidate) {
        (CausalReachability::Reachable, CausalReachability::Reachable) => {
            ReadCursorCausalRelation::Undecidable
        }
        (CausalReachability::Reachable, _) => ReadCursorCausalRelation::CandidateDominatesCurrent,
        (_, CausalReachability::Reachable) => ReadCursorCausalRelation::CurrentDominatesCandidate,
        (CausalReachability::CompleteUnreachable, CausalReachability::CompleteUnreachable) => {
            ReadCursorCausalRelation::Concurrent
        }
        _ => ReadCursorCausalRelation::Undecidable,
    }
}

/// Resolve final causal depths for a selected Event closure. Unrelated missing
/// history does not block a scan; missing predecessors or cycles in this closure
/// do. No receive-time or provisional-order fallback is permitted.
pub fn canonical_event_depths(
    records: &[AcceptedEvent],
    roots: &BTreeSet<String>,
) -> Result<BTreeMap<String, u64>, String> {
    let graph = CanonicalCausalGraph::new(records);
    let mut pending: Vec<_> = roots.iter().cloned().collect();
    let mut dependencies = BTreeMap::new();
    let mut dependents: BTreeMap<String, Vec<String>> = BTreeMap::new();
    while let Some(id) = pending.pop() {
        if dependencies.contains_key(&id) {
            continue;
        }
        let record = graph
            .by_event_id
            .get(id.as_str())
            .ok_or_else(|| format!("canonical predecessor unavailable: {id}"))?;
        let (predecessors, complete) = graph.predecessors(record);
        if !complete {
            return Err(format!("canonical predecessor closure incomplete: {id}"));
        }
        for predecessor in &predecessors {
            dependents
                .entry(predecessor.clone())
                .or_default()
                .push(id.clone());
            pending.push(predecessor.clone());
        }
        dependencies.insert(id, predecessors.len());
    }
    let mut ready: Vec<_> = dependencies
        .iter()
        .filter(|(_, count)| **count == 0)
        .map(|(id, _)| id.clone())
        .collect();
    let mut depths = BTreeMap::new();
    let mut resolved = 0;
    while let Some(id) = ready.pop() {
        let depth = *depths.entry(id.clone()).or_insert(0_u64);
        resolved += 1;
        for dependent in dependents.get(&id).into_iter().flatten() {
            let next_depth = depth.checked_add(1).ok_or("causal depth overflow")?;
            let current = depths.entry(dependent.clone()).or_default();
            *current = (*current).max(next_depth);
            let remaining = dependencies.get_mut(dependent).expect("indexed dependent");
            *remaining -= 1;
            if *remaining == 0 {
                ready.push(dependent.clone());
            }
        }
    }
    if resolved != dependencies.len() {
        return Err("canonical predecessor closure contains a cycle".to_owned());
    }
    Ok(depths)
}

struct CanonicalCausalGraph<'a> {
    by_event_id: BTreeMap<&'a str, &'a AcceptedEvent>,
    event_id_by_digest: BTreeMap<&'a str, &'a str>,
    event_id_by_message_id: BTreeMap<String, &'a str>,
}

impl<'a> CanonicalCausalGraph<'a> {
    fn new(records: &'a [AcceptedEvent]) -> Self {
        let by_event_id = records
            .iter()
            .map(|record| (record.event_id.as_str(), record))
            .collect();
        let event_id_by_digest = records
            .iter()
            .map(|record| (record.canonical_digest.as_str(), record.event_id.as_str()))
            .collect();
        let event_id_by_message_id = records
            .iter()
            .filter(|record| record.kind == arkret_wire::EventKind::MessageCreate.as_str())
            .map(|record| {
                let message_id = record
                    .envelope
                    .get("payload")
                    .and_then(|payload| payload.get("message_id"))
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
                    .unwrap_or_else(|| record.event_id.replacen("ak:event:", "ak:message:", 1));
                (message_id, record.event_id.as_str())
            })
            .collect();
        Self {
            by_event_id,
            event_id_by_digest,
            event_id_by_message_id,
        }
    }

    fn reaches(&self, start: &str, target: &str) -> CausalReachability {
        let mut pending = vec![start.to_owned()];
        let mut visited = BTreeSet::new();
        let mut complete = true;
        while let Some(event_id) = pending.pop() {
            if !visited.insert(event_id.clone()) {
                continue;
            }
            let Some(record) = self.by_event_id.get(event_id.as_str()).copied() else {
                complete = false;
                continue;
            };
            let (predecessors, record_complete) = self.predecessors(record);
            complete &= record_complete;
            for predecessor in predecessors {
                if predecessor == target {
                    return CausalReachability::Reachable;
                }
                if !visited.contains(&predecessor) {
                    pending.push(predecessor);
                }
            }
        }
        if complete {
            CausalReachability::CompleteUnreachable
        } else {
            CausalReachability::Incomplete
        }
    }

    fn predecessors(&self, record: &AcceptedEvent) -> (BTreeSet<String>, bool) {
        let mut predecessors = BTreeSet::new();
        let mut complete = true;
        collect_string_array(
            record.envelope.get("prev_refs"),
            &mut predecessors,
            &mut complete,
        );
        if let Some(refs) = record.envelope.get("refs") {
            let Some(refs) = refs.as_array() else {
                return (predecessors, false);
            };
            for event_ref in refs {
                if event_ref.get("role").and_then(Value::as_str) != Some("after") {
                    continue;
                }
                let Some(id) = event_ref.get("id").and_then(Value::as_str) else {
                    complete = false;
                    continue;
                };
                if let Some(event_id) = self.resolve_event_reference(id) {
                    predecessors.insert(event_id);
                } else {
                    complete = false;
                }
            }
        }
        if let Some(causal_refs) = record.envelope.get("causal_refs") {
            let Some(causal_refs) = causal_refs.as_array() else {
                return (predecessors, false);
            };
            for digest in causal_refs {
                let Some(digest) = digest.as_str() else {
                    complete = false;
                    continue;
                };
                if let Some(event_id) = self.event_id_by_digest.get(digest) {
                    predecessors.insert((*event_id).to_owned());
                } else {
                    complete = false;
                }
            }
        }
        if predecessors.contains(&record.event_id) {
            complete = false;
        }
        if let Some(payload) = record.envelope.get("payload") {
            self.collect_materialized_payload_edges(payload, &mut predecessors, &mut complete);
        }
        predecessors.remove(record.event_id.as_str());
        (predecessors, complete)
    }

    fn collect_materialized_payload_edges(
        &self,
        value: &Value,
        predecessors: &mut BTreeSet<String>,
        complete: &mut bool,
    ) {
        let Some(object) = value.as_object() else {
            return;
        };
        for (field, field_value) in object {
            if matches!(
                field.as_str(),
                // Registered Message-target carriers: `message_redact_payload`
                // and `message_revise_payload` both spell it `message_id`.
                "message_id" | "reply_to_id"
            ) || (field == "target_ref"
                && field_value
                    .as_str()
                    .is_some_and(|id| id.starts_with("ak:event:") || id.starts_with("ak:message:")))
            {
                self.collect_resolved_references(field_value, predecessors, complete);
            } else if field == "basis_event_ids" {
                collect_string_array(Some(field_value), predecessors, complete);
            }
            if field_value.is_object() {
                self.collect_materialized_payload_edges(field_value, predecessors, complete);
            }
        }
    }

    fn collect_resolved_references(
        &self,
        value: &Value,
        predecessors: &mut BTreeSet<String>,
        complete: &mut bool,
    ) {
        let references = match value {
            Value::String(value) => vec![value.as_str()],
            Value::Array(values) => values.iter().filter_map(Value::as_str).collect(),
            Value::Object(object) => object
                .get("id")
                .and_then(Value::as_str)
                .into_iter()
                .collect(),
            _ => Vec::new(),
        };
        if references.is_empty() {
            *complete = false;
        }
        for reference in references {
            if let Some(event_id) = self.resolve_event_reference(reference) {
                predecessors.insert(event_id);
            } else {
                *complete = false;
            }
        }
    }

    fn resolve_event_reference(&self, reference: &str) -> Option<String> {
        if reference.starts_with("ak:event:") {
            Some(reference.to_owned())
        } else if reference.starts_with("ak:message:") {
            self.event_id_by_message_id
                .get(reference)
                .map(|event_id| (*event_id).to_owned())
        } else {
            None
        }
    }
}

fn collect_string_array(value: Option<&Value>, output: &mut BTreeSet<String>, complete: &mut bool) {
    let Some(value) = value else {
        return;
    };
    let Some(values) = value.as_array() else {
        *complete = false;
        return;
    };
    for value in values {
        if let Some(value) = value.as_str() {
            output.insert(value.to_owned());
        } else {
            *complete = false;
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProjectedEvent {
    pub event_id: String,
    pub realm_id: String,
    pub event_kind: arkret_wire::EventKind,
    pub operation_kind: String,
    pub operation_id: Option<String>,
    pub sender: Option<String>,
    pub payload: Value,
    pub created_at: DateTime<Utc>,
    pub received_at: DateTime<Utc>,
}

pub use soland_storage::MessageRecord as MessageState;

#[async_trait::async_trait]
pub trait MessagePort: Send + Sync {
    async fn message(&self, event_id: &str) -> ServiceResult<Option<MessageState>>;
    async fn store_message(&self, message: MessageState) -> ServiceResult<()>;
    async fn messages_for_realm(
        &self,
        realm_id: &str,
        limit: usize,
    ) -> ServiceResult<Vec<MessageState>>;
}

pub use soland_storage::{
    AppletAuthoringPreviewRecord as AppletAuthoringPreviewState,
    AppletTransactionReplayBegin as AppletTransactionReplayResult,
    AppletTransactionReplayRecord as AppletTransactionReplayState,
};

#[async_trait::async_trait]
pub trait AppletPort: Send + Sync {
    async fn applet_identity(
        &self,
        applet_id: &str,
        target_station_id: &str,
    ) -> ServiceResult<Option<Value>>;
    async fn applet(
        &self,
        applet_id: &str,
        effective_scope_key: &str,
    ) -> ServiceResult<Option<Value>>;
    async fn applets(&self) -> ServiceResult<Vec<Value>>;
    async fn compare_and_swap_applet(
        &self,
        applet_id: &str,
        effective_scope_key: &str,
        expected: &Value,
        replacement: Value,
    ) -> ServiceResult<bool>;
    async fn fence_applet_installation(
        &self,
        applet_id: &str,
        effective_scope_key: &str,
        target_station_id: &str,
        expected: &Value,
        replacement: Value,
        fenced_at: DateTime<Utc>,
    ) -> ServiceResult<soland_storage::AppletInstallationFenceOutcome>;
    async fn begin_applet_transaction(
        &self,
        replay: AppletTransactionReplayState,
    ) -> ServiceResult<AppletTransactionReplayResult>;
    async fn complete_applet_transaction(
        &self,
        applet_id: &str,
        source_id: &str,
        idempotency_key: &str,
        outcome: Value,
    ) -> ServiceResult<()>;
    async fn issue_applet_authoring_preview(
        &self,
        candidate: AppletAuthoringPreviewState,
    ) -> ServiceResult<AppletAuthoringPreviewState>;
    async fn current_applet_authoring_preview(
        &self,
        subject_key: &str,
    ) -> ServiceResult<Option<AppletAuthoringPreviewState>>;
}

pub use soland_storage::ProjectionEventAppendOutcome as ProjectedEventAppendResult;

#[derive(Clone, Debug)]
pub struct IdempotentResponse {
    pub authenticated_actor: arkret_wire::ActorId,
    pub operation_id: String,
    pub key: String,
    pub request_hash: String,
    pub status: i32,
    pub body: Value,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// One outbound delivery intent committed together with its Event. Same type
/// the federation service enqueues and the dispatcher claims — there is exactly
/// one shape for "a request this service owes a peer".
use crate::federation::FederationDeliveryRecord;

#[derive(Clone, Debug)]
pub struct CommitAcceptedEventCommand {
    /// Current-authority transaction that orders this Event on its Realm,
    /// Circle or Sidecar stream. One `RealmCommit` accepts exactly one Event,
    /// so the signed commit travels with the Event it admits.
    pub authority_commit: soland_storage::AuthorityCommitTransaction,
    pub event: AcceptedEvent,
    pub device_pairing_authorization: Option<CommitDevicePairingAuthorization>,
    pub contact_projection: Option<CommitContactProjection>,
    /// Station-private pending intent created by `ak.agent.draft.propose`.
    pub agent_draft_pending_intent: Option<soland_storage::AgentDraftPendingIntentCommit>,
    /// Holder-private account-data register mutation owned by this Event.
    ///
    /// This is committed in the same transaction as the canonical Event and
    /// never enters the shared Realm reducer.
    pub actor_private_account_data: Option<CommitAccountDataCas>,
    /// Holder-private consent grant mutation plus its eager cache
    /// invalidation, staged by admission and committed with the Event.
    pub consent_projection: Option<CommitConsentProjection>,
    pub device_revocation_transition: Option<soland_storage::DeviceRevocationTransition>,
    pub device_revocation_gate: Option<soland_storage::DeviceRevocationGateSelector>,
    pub projections: Vec<ProjectedEvent>,
    pub idempotency: Option<IdempotentResponse>,
    pub deliveries: Vec<FederationDeliveryRecord>,
}

/// The holder-private consent effects of one accepted consent command unit.
///
/// `consent-model.md` section 4.1.2 puts the downstream invalidation inside
/// the same transaction boundary as the accepted revoke, so the holder grant
/// mutation and the holder-quarantine CAS commit with the canonical Event.
#[derive(Clone, Debug)]
pub struct CommitConsentProjection {
    pub grant: crate::identity::ConsentGrantRecord,
    pub holder_quarantine: Option<CommitAccountDataCas>,
}

/// One account-data cell replaced by revision CAS inside an Event commit.
#[derive(Clone, Debug)]
pub struct CommitAccountDataCas {
    pub record: crate::identity::AccountDataState,
    pub expected_revision: u64,
    pub conflict_code: String,
}

pub use soland_storage::{
    AppletAuthoringPreviewCommit as CommitAppletAuthoringPreview,
    AppletIdentityCommit as CommitAppletIdentity, AppletRecordCommit as CommitAppletRecord,
    ContactProjectionCommit as CommitContactProjection,
    DevicePairingAuthorizationCommit as CommitDevicePairingAuthorization,
};

#[derive(Clone, Debug)]
pub struct CommitAcceptedEventBatchCommand {
    pub events: Vec<CommitAcceptedEventCommand>,
    pub franking_replay_nonce: Option<soland_storage::FrankingReplayNonceCommit>,
    pub applet_record: Option<CommitAppletRecord>,
    pub applet_authoring_preview: Option<CommitAppletAuthoringPreview>,
    pub agent_membership_cascade: Option<soland_storage::AgentMembershipCascadeCommit>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitAcceptedEventResult {
    pub projections_inserted: usize,
    pub deliveries_inserted: usize,
}

#[async_trait::async_trait]
pub trait EventReadPort: Send + Sync {
    async fn direct_conversation_founding_slot(
        &self,
        founder_id: &str,
        trust_domain_id: &str,
        pair_key: &str,
    ) -> ServiceResult<Option<soland_storage::DirectConversationFoundingSlotRecord>>;
    async fn canonical_event(&self, event_id: &str) -> ServiceResult<Option<AcceptedEvent>>;
    async fn has_canonical_event(&self, event_id: &str) -> ServiceResult<bool>;
    async fn canonical_events(&self) -> ServiceResult<Vec<AcceptedEvent>>;
    async fn canonical_events_for_actor(&self, actor_id: &str)
    -> ServiceResult<Vec<AcceptedEvent>>;
    async fn franking_proofs_for_target(
        &self,
        realm_id: &str,
        received_by: &arkret_identifiers::DidCoreId,
        target_event_id: &str,
    ) -> ServiceResult<Vec<AcceptedEvent>>;
    async fn identity_anchor_account_slot(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> ServiceResult<Option<soland_storage::IdentityAnchorAccountSlot>>;
    async fn realm_event_stats(&self, realm_id: &str) -> ServiceResult<RealmEventStats>;
    async fn realm_events_newest_first(&self, realm_id: &str) -> ServiceResult<Vec<AcceptedEvent>>;
    async fn accepted_event(&self, event_id: &str) -> ServiceResult<Option<AcceptedEvent>>;
    async fn accepted_events(&self) -> ServiceResult<Vec<AcceptedEvent>>;
    async fn projected_event(&self, event_id: &str) -> ServiceResult<Option<ProjectedEvent>>;
    async fn projected_event_by_operation_id(
        &self,
        operation_id: &str,
    ) -> ServiceResult<Option<ProjectedEvent>>;
    async fn projected_events_for_realm(
        &self,
        realm_id: &str,
    ) -> ServiceResult<Vec<ProjectedEvent>>;
    async fn projected_events_for_actor(
        &self,
        actor_id: &str,
    ) -> ServiceResult<Vec<ProjectedEvent>>;
    async fn projected_events_for_kind(
        &self,
        event_kind: arkret_wire::EventKind,
    ) -> ServiceResult<Vec<ProjectedEvent>>;
    async fn append_projected_event(
        &self,
        event: ProjectedEvent,
    ) -> ServiceResult<ProjectedEventAppendResult>;
    async fn accepted_events_for_actor(&self, actor_id: &str) -> ServiceResult<Vec<AcceptedEvent>>;
}

#[async_trait::async_trait]
pub trait ProjectionWritePort: Send + Sync {
    async fn store_space_container_projection(
        &self,
        record: &SpaceContainerProjectionRecord,
    ) -> ServiceResult<()>;
    async fn store_strand_projection(&self, record: &StrandProjectionRecord) -> ServiceResult<()>;
    /// Persist one Circle row together with its complete membership set.
    async fn store_circle_projection(
        &self,
        record: &CircleProjectionRecord,
        members: &[CircleMemberProjectionRecord],
    ) -> ServiceResult<()>;
    async fn store_strand_watch_projection(
        &self,
        record: &StrandWatchProjectionRecord,
    ) -> ServiceResult<()>;
    async fn store_morph_projection(&self, record: &MorphProjectionRecord) -> ServiceResult<()>;
    async fn store_realm_organization_statement(
        &self,
        record: &RealmOrganizationStatementRecord,
    ) -> ServiceResult<()>;
}

/// Publication evidence per accepted Event canonical digest
/// (`authz/offline-publication.md` §2.1).
#[async_trait::async_trait]
pub trait PublicationEvidencePort: Send + Sync {
    /// Store the evidence for an Event not seen before and return whatever is
    /// stored afterwards. An Event that is already present wins, so the
    /// original `accepted_at` survives an idempotent retry verbatim.
    async fn store_publication_evidence(
        &self,
        record: PublicationEvidenceRecord,
    ) -> ServiceResult<PublicationEvidenceRecord>;
    async fn publication_evidence(
        &self,
        event_id: &arkret_wire::EventId,
    ) -> ServiceResult<Option<PublicationEvidenceRecord>>;
    async fn publication_evidence_for_events(
        &self,
        event_ids: &[arkret_wire::EventId],
    ) -> ServiceResult<Vec<PublicationEvidenceRecord>>;
}

#[derive(Clone)]
pub struct EventQueryService {
    events: Arc<dyn EventReadPort>,
    messages: Arc<dyn MessagePort>,
    applets: Arc<dyn AppletPort>,
    projections: Arc<dyn ProjectionWritePort>,
    publication_evidence: Arc<dyn PublicationEvidencePort>,
}

fn active_agent_accountability(
    original_event: &AcceptedEvent,
    events: &[AcceptedEvent],
    query: &ActiveAgentAccountabilityQuery,
) -> bool {
    let controller_actor = arkret_wire::ActorId::account(query.controller_account_id.clone());
    if query.agent_account_id.station_id != query.controller_account_id.station_id
        || accepted_event_actor(original_event).as_ref() != Some(&controller_actor)
    {
        return false;
    }
    let controller_principal_id = query.controller_account_id.principal_id.as_str();
    let agent_id = query.agent_account_id.principal_id.as_str();
    if arkret_wire::EventKind::AgentProvision == original_event.kind {
        let Ok(event) =
            serde_json::from_value::<arkret_wire::Event>(original_event.envelope.clone())
        else {
            return false;
        };
        let Ok(provision) = AgentProvisionPayload::try_from(&event) else {
            return false;
        };
        return provision.validate().is_ok()
            && original_event.received_at <= query.accepted_at
            && provision.controller_principal_id.as_str() == controller_principal_id
            && provision.agent_id.as_str() == agent_id
            && matches!(
                provision.accountability_scope,
                AgentProvisionAccountabilityScope::AgentOperator
            );
    }
    let original_payload = original_event
        .envelope
        .get("payload")
        .unwrap_or(&original_event.envelope);
    let Ok(original_grant) =
        serde_json::from_value::<AccountabilityGrantPayload>(original_payload.clone())
    else {
        return false;
    };
    let Ok(original_scope_key) = accountability_scope_key(&original_grant) else {
        return false;
    };
    let current_grant = events
        .iter()
        .filter(|candidate| {
            candidate.kind == arkret_wire::event_kind_str::IDENTITY_ACCOUNTABILITY_GRANT
                && candidate.received_at <= query.accepted_at
                && candidate.realm_id == original_event.realm_id
                && accepted_event_actor(candidate).as_ref() == Some(&controller_actor)
                && accepted_event_executor(candidate).as_ref() == Some(&controller_actor)
        })
        .filter_map(|candidate| {
            let payload = candidate
                .envelope
                .get("payload")
                .unwrap_or(&candidate.envelope);
            let grant =
                serde_json::from_value::<AccountabilityGrantPayload>(payload.clone()).ok()?;
            (grant.issuer_id.as_str() == controller_principal_id
                && grant.subject_id.as_str() == agent_id
                && accountability_scope_key(&grant).ok().as_deref()
                    == Some(original_scope_key.as_str()))
            .then_some((accepted_event_order_key(candidate), grant))
        })
        .max_by(|left, right| left.0.cmp(&right.0))
        .map(|(_, grant)| grant);
    let signed_by_controller =
        accepted_event_executor(original_event).as_ref() == Some(&controller_actor);
    let projected_scopes = active_accountability_scopes(
        events,
        original_event.realm_id.as_deref(),
        &query.controller_account_id,
        agent_id,
        query.accepted_at,
    );
    original_event.kind == arkret_wire::event_kind_str::IDENTITY_ACCOUNTABILITY_GRANT
        && signed_by_controller
        && original_grant.issuer_id.as_str() == controller_principal_id
        && original_grant.subject_id.as_str() == agent_id
        && !projected_scopes.is_empty()
        && current_grant.is_some_and(|grant| grant.validate_lifecycle_at(query.accepted_at).is_ok())
}

fn accepted_event_actor(record: &AcceptedEvent) -> Option<arkret_wire::ActorId> {
    let actor: arkret_wire::ActorId =
        serde_json::from_value(record.envelope.get("actor_id")?.clone()).ok()?;
    (record.actor_id == actor.to_string()).then_some(actor)
}

pub fn accepted_event_executor(record: &AcceptedEvent) -> Option<arkret_wire::ActorId> {
    let actor = accepted_event_actor(record)?;
    match record.envelope.get("executed_by") {
        None => Some(actor),
        Some(value) => serde_json::from_value(value.clone()).ok(),
    }
}

/// The register one accountability grant replaces.
///
/// The retired composite cell subject was
/// `(issuer_id, subject_id, scope_set_component)`; the same three coordinates
/// still identify the register, so the key is rebuilt from the payload instead
/// of from a cell identifier.
fn accountability_scope_key(grant: &AccountabilityGrantPayload) -> arkret_wire::Result<String> {
    let scopes = grant.accountability_scope.canonical_set()?;
    let mut key = String::new();
    key.push_str(grant.issuer_id.as_str());
    key.push('\u{1f}');
    key.push_str(grant.subject_id.as_str());
    for scope in scopes {
        key.push('\u{1f}');
        key.push_str(scope.as_str());
    }
    Ok(key)
}

/// Last-writer-wins ordering between two accepted Events on one register.
///
/// The per-actor sequence number was retired together with the producer event
/// chain, so the Station-assigned receipt time orders the two grants and the
/// Event id keeps the comparison total.
fn accepted_event_order_key(record: &AcceptedEvent) -> (DateTime<Utc>, String) {
    (record.received_at, record.event_id.clone())
}

fn active_accountability_scopes(
    events: &[AcceptedEvent],
    realm_id: Option<&str>,
    issuer_account: &arkret_wire::AccountId,
    subject: &str,
    at: DateTime<Utc>,
) -> BTreeSet<AccountabilityScopeKind> {
    let issuer = issuer_account.principal_id.as_str();
    let issuer_actor = arkret_wire::ActorId::account(issuer_account.clone());
    let mut latest_by_scope =
        BTreeMap::<String, ((DateTime<Utc>, String), AccountabilityGrantPayload)>::new();
    for candidate in events.iter().filter(|candidate| {
        candidate.kind == arkret_wire::event_kind_str::IDENTITY_ACCOUNTABILITY_GRANT
            && candidate.received_at <= at
            && candidate.realm_id.as_deref() == realm_id
            && accepted_event_actor(candidate).as_ref() == Some(&issuer_actor)
            && accepted_event_executor(candidate).as_ref() == Some(&issuer_actor)
    }) {
        let payload = candidate
            .envelope
            .get("payload")
            .unwrap_or(&candidate.envelope);
        let Ok(grant) = serde_json::from_value::<AccountabilityGrantPayload>(payload.clone())
        else {
            continue;
        };
        if grant.issuer_id.as_str() != issuer || grant.subject_id.as_str() != subject {
            continue;
        }
        let Ok(scope_key) = accountability_scope_key(&grant) else {
            continue;
        };
        let order = accepted_event_order_key(candidate);
        let entry = latest_by_scope
            .entry(scope_key)
            .or_insert_with(|| (order.clone(), grant.clone()));
        if order > entry.0 {
            *entry = (order, grant);
        }
    }
    latest_by_scope
        .into_values()
        .filter_map(|(_, grant)| {
            grant
                .validate_lifecycle_at(at)
                .is_ok()
                .then(|| grant.accountability_scope.canonical_set().ok())
                .flatten()
        })
        .flatten()
        .collect()
}

impl EventQueryService {
    pub async fn has_active_agent_accountability(
        &self,
        query: &ActiveAgentAccountabilityQuery,
    ) -> ServiceResult<bool> {
        let Some(original_event) = self
            .events
            .canonical_event(&query.accountability_event_id)
            .await?
        else {
            return Ok(false);
        };
        let events = self.events.canonical_events().await?;
        Ok(active_agent_accountability(&original_event, &events, query))
    }

    pub async fn direct_conversation_founding_slot(
        &self,
        founder_id: &str,
        trust_domain_id: &str,
        pair_key: &str,
    ) -> ServiceResult<Option<soland_storage::DirectConversationFoundingSlotRecord>> {
        self.events
            .direct_conversation_founding_slot(founder_id, trust_domain_id, pair_key)
            .await
    }
    pub async fn canonical_event(&self, event_id: &str) -> ServiceResult<Option<AcceptedEvent>> {
        self.events.canonical_event(event_id).await
    }
    pub async fn has_canonical_event(&self, event_id: &str) -> ServiceResult<bool> {
        self.events.has_canonical_event(event_id).await
    }
    pub async fn canonical_events(&self) -> ServiceResult<Vec<AcceptedEvent>> {
        self.events.canonical_events().await
    }
    pub async fn canonical_events_for_actor(
        &self,
        actor_id: &str,
    ) -> ServiceResult<Vec<AcceptedEvent>> {
        self.events.canonical_events_for_actor(actor_id).await
    }
    pub async fn franking_proofs_for_target(
        &self,
        realm_id: &str,
        received_by: &arkret_identifiers::DidCoreId,
        target_event_id: &str,
    ) -> ServiceResult<Vec<AcceptedEvent>> {
        self.events
            .franking_proofs_for_target(realm_id, received_by, target_event_id)
            .await
    }
    pub async fn identity_anchor_account_slot(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> ServiceResult<Option<soland_storage::IdentityAnchorAccountSlot>> {
        self.events.identity_anchor_account_slot(account_id).await
    }
    pub async fn realm_event_stats(&self, realm_id: &str) -> ServiceResult<RealmEventStats> {
        self.events.realm_event_stats(realm_id).await
    }
    pub async fn realm_events_newest_first(
        &self,
        realm_id: &str,
    ) -> ServiceResult<Vec<AcceptedEvent>> {
        self.events.realm_events_newest_first(realm_id).await
    }

    pub fn new(
        events: Arc<dyn EventReadPort>,
        messages: Arc<dyn MessagePort>,
        applets: Arc<dyn AppletPort>,
        projections: Arc<dyn ProjectionWritePort>,
        publication_evidence: Arc<dyn PublicationEvidencePort>,
    ) -> Self {
        Self {
            events,
            messages,
            applets,
            projections,
            publication_evidence,
        }
    }

    /// Persist the authority acceptance evidence for one Event, or return the
    /// evidence already stored for it.
    pub async fn store_publication_evidence(
        &self,
        record: PublicationEvidenceRecord,
    ) -> ServiceResult<PublicationEvidenceRecord> {
        self.publication_evidence
            .store_publication_evidence(record)
            .await
    }

    pub async fn publication_evidence(
        &self,
        event_id: &arkret_wire::EventId,
    ) -> ServiceResult<Option<PublicationEvidenceRecord>> {
        self.publication_evidence
            .publication_evidence(event_id)
            .await
    }

    pub async fn publication_evidence_for_events(
        &self,
        event_ids: &[arkret_wire::EventId],
    ) -> ServiceResult<Vec<PublicationEvidenceRecord>> {
        self.publication_evidence
            .publication_evidence_for_events(event_ids)
            .await
    }

    pub async fn accepted_event(&self, event_id: &str) -> ServiceResult<Option<AcceptedEvent>> {
        self.events.accepted_event(event_id).await
    }

    pub async fn accepted_events(&self) -> ServiceResult<Vec<AcceptedEvent>> {
        self.events.accepted_events().await
    }

    pub async fn projected_event(&self, event_id: &str) -> ServiceResult<Option<ProjectedEvent>> {
        self.events.projected_event(event_id).await
    }

    pub async fn projected_event_by_operation_id(
        &self,
        operation_id: &str,
    ) -> ServiceResult<Option<ProjectedEvent>> {
        self.events
            .projected_event_by_operation_id(operation_id)
            .await
    }

    pub async fn projected_events_for_realm(
        &self,
        realm_id: &str,
    ) -> ServiceResult<Vec<ProjectedEvent>> {
        self.events.projected_events_for_realm(realm_id).await
    }

    pub async fn projected_events_for_actor(
        &self,
        actor_id: &str,
    ) -> ServiceResult<Vec<ProjectedEvent>> {
        self.events.projected_events_for_actor(actor_id).await
    }

    pub async fn projected_events_for_kind(
        &self,
        event_kind: arkret_wire::EventKind,
    ) -> ServiceResult<Vec<ProjectedEvent>> {
        self.events.projected_events_for_kind(event_kind).await
    }

    pub async fn append_projected_event(
        &self,
        event: ProjectedEvent,
    ) -> ServiceResult<ProjectedEventAppendResult> {
        self.events.append_projected_event(event).await
    }

    pub async fn accepted_events_for_actor(
        &self,
        actor_id: &str,
    ) -> ServiceResult<Vec<AcceptedEvent>> {
        self.events.accepted_events_for_actor(actor_id).await
    }

    pub async fn message(&self, event_id: &str) -> ServiceResult<Option<MessageState>> {
        self.messages.message(event_id).await
    }

    pub async fn store_message(&self, message: MessageState) -> ServiceResult<()> {
        self.messages.store_message(message).await
    }

    pub async fn messages_for_realm(
        &self,
        realm_id: &str,
        limit: usize,
    ) -> ServiceResult<Vec<MessageState>> {
        self.messages.messages_for_realm(realm_id, limit).await
    }

    pub async fn applet(
        &self,
        applet_id: &str,
        effective_scope_key: &str,
    ) -> ServiceResult<Option<Value>> {
        self.applets.applet(applet_id, effective_scope_key).await
    }
    pub async fn applet_identity(
        &self,
        applet_id: &str,
        target_station_id: &str,
    ) -> ServiceResult<Option<Value>> {
        self.applets
            .applet_identity(applet_id, target_station_id)
            .await
    }
    pub async fn applets(&self) -> ServiceResult<Vec<Value>> {
        self.applets.applets().await
    }
    pub async fn compare_and_swap_applet(
        &self,
        applet_id: &str,
        effective_scope_key: &str,
        expected: &Value,
        replacement: Value,
    ) -> ServiceResult<bool> {
        self.applets
            .compare_and_swap_applet(applet_id, effective_scope_key, expected, replacement)
            .await
    }
    pub async fn fence_applet_installation(
        &self,
        applet_id: &str,
        effective_scope_key: &str,
        target_station_id: &str,
        expected: &Value,
        replacement: Value,
        fenced_at: DateTime<Utc>,
    ) -> ServiceResult<soland_storage::AppletInstallationFenceOutcome> {
        self.applets
            .fence_applet_installation(
                applet_id,
                effective_scope_key,
                target_station_id,
                expected,
                replacement,
                fenced_at,
            )
            .await
    }
    pub async fn begin_applet_transaction(
        &self,
        replay: AppletTransactionReplayState,
    ) -> ServiceResult<AppletTransactionReplayResult> {
        self.applets.begin_applet_transaction(replay).await
    }
    pub async fn complete_applet_transaction(
        &self,
        applet_id: &str,
        source_id: &str,
        idempotency_key: &str,
        outcome: Value,
    ) -> ServiceResult<()> {
        self.applets
            .complete_applet_transaction(applet_id, source_id, idempotency_key, outcome)
            .await
    }

    pub async fn issue_applet_authoring_preview(
        &self,
        candidate: AppletAuthoringPreviewState,
    ) -> ServiceResult<AppletAuthoringPreviewState> {
        self.applets.issue_applet_authoring_preview(candidate).await
    }

    pub async fn current_applet_authoring_preview(
        &self,
        subject_key: &str,
    ) -> ServiceResult<Option<AppletAuthoringPreviewState>> {
        self.applets
            .current_applet_authoring_preview(subject_key)
            .await
    }

    pub async fn store_space_container_projection(
        &self,
        record: &SpaceContainerProjectionRecord,
    ) -> ServiceResult<()> {
        self.projections
            .store_space_container_projection(record)
            .await
    }

    pub async fn store_strand_projection(
        &self,
        record: &StrandProjectionRecord,
    ) -> ServiceResult<()> {
        self.projections.store_strand_projection(record).await
    }

    pub async fn store_morph_projection(
        &self,
        record: &MorphProjectionRecord,
    ) -> ServiceResult<()> {
        self.projections.store_morph_projection(record).await
    }

    pub async fn store_circle_projection(
        &self,
        record: &CircleProjectionRecord,
        members: &[CircleMemberProjectionRecord],
    ) -> ServiceResult<()> {
        self.projections
            .store_circle_projection(record, members)
            .await
    }

    pub async fn store_strand_watch_projection(
        &self,
        record: &StrandWatchProjectionRecord,
    ) -> ServiceResult<()> {
        self.projections.store_strand_watch_projection(record).await
    }

    pub async fn store_realm_organization_statement(
        &self,
        record: &RealmOrganizationStatementRecord,
    ) -> ServiceResult<()> {
        self.projections
            .store_realm_organization_statement(record)
            .await
    }
}

#[derive(Clone, Debug)]
pub struct MlsCommitState {
    pub group_id: String,
    pub effective_scope: ScopeRef,
    pub epoch: u64,
    pub creator_device_id: String,
    pub genesis_event_ref: String,
    pub governance_binding: MlsGovernanceBindingPayload,
    pub accepted_commit_ref: Option<String>,
}

#[derive(Clone, Debug)]
pub struct InitializeMlsGroupCommand {
    pub effective_scope: ScopeRef,
    pub group_id: String,
    pub leader_actor_id: String,
    pub creator_device_id: String,
    pub genesis_event_ref: String,
    pub governance_binding: MlsGovernanceBindingPayload,
    pub committed_at: i64,
}

#[derive(Clone, Debug)]
pub struct AdvanceMlsEpochCommand {
    pub expected_previous_epoch: u64,
    pub effective_scope: ScopeRef,
    pub group_id: String,
    pub leader_actor_id: String,
    pub governance_binding: MlsGovernanceBindingPayload,
    pub accepted_commit_ref: String,
    pub committed_at: i64,
}

#[async_trait::async_trait]
pub trait MlsCommitReadPort: Send + Sync {
    async fn commits(&self) -> ServiceResult<Vec<MlsCommitState>>;
    async fn commit(
        &self,
        effective_scope: &ScopeRef,
        group_id: &str,
    ) -> ServiceResult<Option<MlsCommitState>>;
    async fn initialize_group(
        &self,
        command: InitializeMlsGroupCommand,
    ) -> ServiceResult<Option<MlsCommitState>>;
    async fn advance_epoch(
        &self,
        command: AdvanceMlsEpochCommand,
    ) -> ServiceResult<Option<MlsCommitState>>;
}

#[derive(Clone)]
pub struct MlsCommitQueryService {
    commits: Arc<dyn MlsCommitReadPort>,
}

impl MlsCommitQueryService {
    pub fn new(commits: Arc<dyn MlsCommitReadPort>) -> Self {
        Self { commits }
    }

    pub async fn commits(&self) -> ServiceResult<Vec<MlsCommitState>> {
        self.commits.commits().await
    }

    pub async fn commit(
        &self,
        effective_scope: &ScopeRef,
        group_id: &str,
    ) -> ServiceResult<Option<MlsCommitState>> {
        self.commits.commit(effective_scope, group_id).await
    }

    pub async fn initialize_group(
        &self,
        command: InitializeMlsGroupCommand,
    ) -> ServiceResult<Option<MlsCommitState>> {
        self.commits.initialize_group(command).await
    }

    pub async fn advance_epoch(
        &self,
        command: AdvanceMlsEpochCommand,
    ) -> ServiceResult<Option<MlsCommitState>> {
        self.commits.advance_epoch(command).await
    }
}

pub struct ClaimMlsKeyPackageCommand<'a> {
    pub id: &'a str,
    pub target: ClaimMlsKeyPackageTarget<'a>,
    pub intended_realm_id: Option<&'a str>,
    pub device_authorize_event_id: Option<&'a str>,
    pub agent_key_authorize_event_id: Option<&'a str>,
    pub device_revocation_gate: Option<&'a soland_storage::DeviceRevocationGateSelector>,
    pub claimed_at: i64,
    pub claim_expires_at_unix_ms: Option<i64>,
}

pub enum ClaimMlsKeyPackageTarget<'a> {
    Group(&'a str),
    Retire,
    Revoke,
}

pub use soland_storage::{
    MlsKeyPackageRow as MlsKeyPackageState,
    PeerKeyPackageClaimLedgerRecord as PeerKeyPackageClaimLedgerState,
    PersistedKeyPackageClaimState, PersistedKeyPackageReusePolicy,
};

pub struct PeerKeyPackageClaimCommand<'a> {
    pub keypackage_id: &'a str,
    pub mls_group_id: &'a str,
    pub device_authorize_event_id: Option<&'a str>,
    pub agent_key_authorize_event_id: Option<&'a str>,
    pub device_revocation_gate: Option<&'a soland_storage::DeviceRevocationGateSelector>,
    pub claimed_at_unix_ms: i64,
    pub claim_expires_at_unix_ms: i64,
    pub ledger: &'a PeerKeyPackageClaimLedgerState,
}

pub struct PeerClaimTerminalTransitionCommand<'a> {
    pub source_id: &'a str,
    pub claim_request_id: &'a str,
    pub request_digest: &'a str,
    pub expected_outcome: &'a Value,
    pub terminal_state: &'a str,
    pub terminal_receipt: &'a Value,
    pub now_unix_ms: i64,
}

pub use soland_storage::{
    PeerKeyPackageClaimAttemptResult as PeerKeyPackageClaimResult,
    PeerKeyPackageClaimLedgerWriteResult,
};

#[async_trait::async_trait]
pub trait MlsKeyPackageMaintenancePort: Send + Sync {
    async fn store_key_package(&self, record: &MlsKeyPackageState) -> ServiceResult<bool>;
    async fn key_package(&self, id: &str) -> ServiceResult<Option<MlsKeyPackageState>>;
    async fn key_package_by_ref(
        &self,
        keypackage_ref: &str,
    ) -> ServiceResult<Option<MlsKeyPackageState>>;
    async fn claim_key_package(
        &self,
        command: ClaimMlsKeyPackageCommand<'_>,
    ) -> ServiceResult<Option<MlsKeyPackageState>>;
    async fn consume_key_package_claim(
        &self,
        id: &str,
        mls_group_id: &str,
        now_unix_ms: i64,
        peer_consume_receipt: Option<&Value>,
    ) -> ServiceResult<Option<MlsKeyPackageState>>;
    async fn peer_claim(
        &self,
        source_id: &str,
        claim_request_id: &str,
    ) -> ServiceResult<Option<PeerKeyPackageClaimLedgerState>>;
    async fn peer_claim_by_keypackage_id(
        &self,
        keypackage_id: &str,
    ) -> ServiceResult<Option<PeerKeyPackageClaimLedgerState>>;
    async fn claim_peer_key_package(
        &self,
        attempt: PeerKeyPackageClaimCommand<'_>,
    ) -> ServiceResult<PeerKeyPackageClaimResult>;
    async fn store_peer_claim_terminal(
        &self,
        record: &PeerKeyPackageClaimLedgerState,
    ) -> ServiceResult<PeerKeyPackageClaimLedgerWriteResult>;
    async fn attach_peer_claim_terminal_receipt(
        &self,
        source_id: &str,
        claim_request_id: &str,
        request_digest: &str,
        terminal_receipt: &Value,
        updated_at: i64,
    ) -> ServiceResult<Option<PeerKeyPackageClaimLedgerState>>;
    async fn attach_peer_claim_consume_receipt(
        &self,
        source_id: &str,
        claim_request_id: &str,
        request_digest: &str,
        consume_receipt: &Value,
        now_unix_ms: i64,
    ) -> ServiceResult<Option<PeerKeyPackageClaimLedgerState>>;
    async fn transition_peer_claim_consumed(
        &self,
        source_id: &str,
        claim_request_id: &str,
        request_digest: &str,
        expected_outcome: &Value,
        consume_receipt: &Value,
        consumed_at_unix_ms: i64,
    ) -> ServiceResult<Option<PeerKeyPackageClaimLedgerState>>;
    async fn transition_peer_claim_terminal(
        &self,
        transition: PeerClaimTerminalTransitionCommand<'_>,
    ) -> ServiceResult<Option<PeerKeyPackageClaimLedgerState>>;
    async fn revoke_expired_peer_claims(&self, now_unix_ms: i64) -> ServiceResult<Vec<String>>;
    async fn key_packages(&self) -> ServiceResult<Vec<MlsKeyPackageState>>;
    async fn key_packages_claimed_by_group(
        &self,
        mls_group_id: &str,
    ) -> ServiceResult<Vec<MlsKeyPackageState>>;
    async fn retire_owner_account_keypackages(
        &self,
        owner_account_pk: soland_storage::AccountPk,
        retired_at: i64,
    ) -> ServiceResult<usize>;
    async fn enqueue_welcome(&self, welcome: MlsWelcomeState) -> ServiceResult<()>;
}

#[derive(Clone, Debug)]
pub struct MlsWelcomeState {
    pub id: String,
    pub group_id: String,
    pub recipient_actor_id: String,
    pub recipient_device_id: Option<String>,
    pub recipient_endpoint_verification_method: Option<String>,
    pub intended_realm_id: Option<String>,
    pub welcome_bytes: Vec<u8>,
    pub key_package_id: String,
    pub epoch: u64,
    pub commit_ref: Option<String>,
    pub governance_binding: MlsGovernanceBindingPayload,
    pub enqueued_at: i64,
    pub delivered_at: Option<i64>,
}

#[derive(Clone)]
pub struct MlsKeyPackageService {
    key_packages: Arc<dyn MlsKeyPackageMaintenancePort>,
}

impl MlsKeyPackageService {
    pub fn new(key_packages: Arc<dyn MlsKeyPackageMaintenancePort>) -> Self {
        Self { key_packages }
    }

    pub async fn retire_owner_account_keypackages(
        &self,
        owner_account_pk: soland_storage::AccountPk,
        retired_at: i64,
    ) -> ServiceResult<usize> {
        self.key_packages
            .retire_owner_account_keypackages(owner_account_pk, retired_at)
            .await
    }

    pub async fn store_key_package(&self, record: &MlsKeyPackageState) -> ServiceResult<bool> {
        self.key_packages.store_key_package(record).await
    }
    pub async fn key_package(&self, id: &str) -> ServiceResult<Option<MlsKeyPackageState>> {
        self.key_packages.key_package(id).await
    }
    pub async fn key_package_by_ref(
        &self,
        keypackage_ref: &str,
    ) -> ServiceResult<Option<MlsKeyPackageState>> {
        self.key_packages.key_package_by_ref(keypackage_ref).await
    }
    pub async fn claim_key_package(
        &self,
        command: ClaimMlsKeyPackageCommand<'_>,
    ) -> ServiceResult<Option<MlsKeyPackageState>> {
        self.key_packages.claim_key_package(command).await
    }
    pub async fn consume_key_package_claim(
        &self,
        id: &str,
        mls_group_id: &str,
        now_unix_ms: i64,
        peer_consume_receipt: Option<&Value>,
    ) -> ServiceResult<Option<MlsKeyPackageState>> {
        self.key_packages
            .consume_key_package_claim(id, mls_group_id, now_unix_ms, peer_consume_receipt)
            .await
    }
    pub async fn peer_claim(
        &self,
        source_id: &str,
        claim_request_id: &str,
    ) -> ServiceResult<Option<PeerKeyPackageClaimLedgerState>> {
        self.key_packages
            .peer_claim(source_id, claim_request_id)
            .await
    }
    pub async fn peer_claim_by_keypackage_id(
        &self,
        keypackage_id: &str,
    ) -> ServiceResult<Option<PeerKeyPackageClaimLedgerState>> {
        self.key_packages
            .peer_claim_by_keypackage_id(keypackage_id)
            .await
    }
    pub async fn claim_peer_key_package(
        &self,
        attempt: PeerKeyPackageClaimCommand<'_>,
    ) -> ServiceResult<PeerKeyPackageClaimResult> {
        self.key_packages.claim_peer_key_package(attempt).await
    }
    pub async fn store_peer_claim_terminal(
        &self,
        record: &PeerKeyPackageClaimLedgerState,
    ) -> ServiceResult<PeerKeyPackageClaimLedgerWriteResult> {
        self.key_packages.store_peer_claim_terminal(record).await
    }
    pub async fn attach_peer_claim_terminal_receipt(
        &self,
        source_id: &str,
        claim_request_id: &str,
        request_digest: &str,
        terminal_receipt: &Value,
        updated_at: i64,
    ) -> ServiceResult<Option<PeerKeyPackageClaimLedgerState>> {
        self.key_packages
            .attach_peer_claim_terminal_receipt(
                source_id,
                claim_request_id,
                request_digest,
                terminal_receipt,
                updated_at,
            )
            .await
    }
    pub async fn attach_peer_claim_consume_receipt(
        &self,
        source_id: &str,
        claim_request_id: &str,
        request_digest: &str,
        consume_receipt: &Value,
        now_unix_ms: i64,
    ) -> ServiceResult<Option<PeerKeyPackageClaimLedgerState>> {
        self.key_packages
            .attach_peer_claim_consume_receipt(
                source_id,
                claim_request_id,
                request_digest,
                consume_receipt,
                now_unix_ms,
            )
            .await
    }
    pub async fn transition_peer_claim_terminal(
        &self,
        transition: PeerClaimTerminalTransitionCommand<'_>,
    ) -> ServiceResult<Option<PeerKeyPackageClaimLedgerState>> {
        self.key_packages
            .transition_peer_claim_terminal(transition)
            .await
    }
    pub async fn transition_peer_claim_consumed(
        &self,
        source_id: &str,
        claim_request_id: &str,
        request_digest: &str,
        expected_outcome: &Value,
        consume_receipt: &Value,
        consumed_at_unix_ms: i64,
    ) -> ServiceResult<Option<PeerKeyPackageClaimLedgerState>> {
        self.key_packages
            .transition_peer_claim_consumed(
                source_id,
                claim_request_id,
                request_digest,
                expected_outcome,
                consume_receipt,
                consumed_at_unix_ms,
            )
            .await
    }
    pub async fn revoke_expired_peer_claims(&self, now_unix_ms: i64) -> ServiceResult<Vec<String>> {
        self.key_packages
            .revoke_expired_peer_claims(now_unix_ms)
            .await
    }
    pub async fn key_packages(&self) -> ServiceResult<Vec<MlsKeyPackageState>> {
        self.key_packages.key_packages().await
    }
    pub async fn key_packages_claimed_by_group(
        &self,
        mls_group_id: &str,
    ) -> ServiceResult<Vec<MlsKeyPackageState>> {
        self.key_packages
            .key_packages_claimed_by_group(mls_group_id)
            .await
    }

    pub async fn enqueue_welcome(&self, welcome: MlsWelcomeState) -> ServiceResult<()> {
        self.key_packages.enqueue_welcome(welcome).await
    }
}

pub use soland_storage::RealmMetaRecord as RealmMetadata;

#[async_trait::async_trait]
pub trait RealmMetadataPort: Send + Sync {
    async fn realm_metadata(&self, realm_id: &str) -> ServiceResult<Option<RealmMetadata>>;
    async fn realm_metadata_list(&self) -> ServiceResult<Vec<(String, RealmMetadata)>>;
    async fn store_realm_metadata(
        &self,
        realm_id: &str,
        metadata: RealmMetadata,
    ) -> ServiceResult<()>;
    async fn delete_realm_metadata(&self, realm_id: &str) -> ServiceResult<()>;
}

#[derive(Clone)]
pub struct RealmQueryService {
    realms: Arc<dyn RealmMetadataPort>,
}

impl RealmQueryService {
    pub fn new(realms: Arc<dyn RealmMetadataPort>) -> Self {
        Self { realms }
    }

    pub async fn realm_metadata(&self, realm_id: &str) -> ServiceResult<Option<RealmMetadata>> {
        self.realms.realm_metadata(realm_id).await
    }

    pub async fn realm_metadata_list(&self) -> ServiceResult<Vec<(String, RealmMetadata)>> {
        self.realms.realm_metadata_list().await
    }

    pub async fn store_realm_metadata(
        &self,
        realm_id: &str,
        metadata: RealmMetadata,
    ) -> ServiceResult<()> {
        self.realms.store_realm_metadata(realm_id, metadata).await
    }
    pub async fn delete_realm_metadata(&self, realm_id: &str) -> ServiceResult<()> {
        self.realms.delete_realm_metadata(realm_id).await
    }
}

#[async_trait::async_trait]
pub trait RealmInvitePort: Send + Sync {
    async fn get(&self, invite_id: &str) -> ServiceResult<Option<RealmInviteState>>;
    async fn put(&self, record: RealmInviteState) -> ServiceResult<()>;
    async fn snapshot_all(&self) -> ServiceResult<Vec<RealmInviteState>>;
}

pub use soland_storage::{
    InviteLocatorInsertOutcome as InviteLocatorInsertResult,
    InviteLocatorRecord as InviteLocatorState,
    InviteLocatorRotateMutation as InviteLocatorRotateCommand,
    RealmInviteRecord as RealmInviteState,
};

#[async_trait::async_trait]
pub trait InviteLocatorPort: Send + Sync {
    async fn insert(
        &self,
        record: &InviteLocatorState,
        active_limit: usize,
        now: DateTime<Utc>,
    ) -> ServiceResult<InviteLocatorInsertResult>;
    async fn resolve_and_consume(
        &self,
        token_digest: &str,
        now: DateTime<Utc>,
    ) -> ServiceResult<Option<InviteLocatorState>>;
    async fn rotate(
        &self,
        subject_id: &str,
        old_locator_id: &str,
        mutation: &InviteLocatorRotateCommand,
        now: DateTime<Utc>,
    ) -> ServiceResult<Option<InviteLocatorState>>;
    async fn revoke(
        &self,
        subject_id: &str,
        locator_id: &str,
        now: DateTime<Utc>,
    ) -> ServiceResult<Option<InviteLocatorState>>;
}

#[derive(Clone)]
pub struct RealmInviteService {
    invites: Arc<dyn RealmInvitePort>,
    locators: Arc<dyn InviteLocatorPort>,
}

impl RealmInviteService {
    pub fn new(invites: Arc<dyn RealmInvitePort>, locators: Arc<dyn InviteLocatorPort>) -> Self {
        Self { invites, locators }
    }

    pub async fn get(&self, invite_id: &str) -> ServiceResult<Option<RealmInviteState>> {
        self.invites.get(invite_id).await
    }

    pub async fn put(&self, record: RealmInviteState) -> ServiceResult<()> {
        self.invites.put(record).await
    }

    pub async fn snapshot_all(&self) -> ServiceResult<Vec<RealmInviteState>> {
        self.invites.snapshot_all().await
    }

    pub async fn insert_locator(
        &self,
        record: &InviteLocatorState,
        active_limit: usize,
        now: DateTime<Utc>,
    ) -> ServiceResult<InviteLocatorInsertResult> {
        self.locators.insert(record, active_limit, now).await
    }

    pub async fn resolve_and_consume_locator(
        &self,
        token_digest: &str,
        now: DateTime<Utc>,
    ) -> ServiceResult<Option<InviteLocatorState>> {
        self.locators.resolve_and_consume(token_digest, now).await
    }

    pub async fn rotate_locator(
        &self,
        subject_id: &str,
        old_locator_id: &str,
        mutation: &InviteLocatorRotateCommand,
        now: DateTime<Utc>,
    ) -> ServiceResult<Option<InviteLocatorState>> {
        self.locators
            .rotate(subject_id, old_locator_id, mutation, now)
            .await
    }

    pub async fn revoke_locator(
        &self,
        subject_id: &str,
        locator_id: &str,
        now: DateTime<Utc>,
    ) -> ServiceResult<Option<InviteLocatorState>> {
        self.locators.revoke(subject_id, locator_id, now).await
    }
}

#[derive(Clone)]
pub struct EventService {
    commits: Arc<dyn EventCommitPort>,
}

#[async_trait::async_trait]
pub trait EventCommitPort: Send + Sync {
    async fn commit_accepted_event(
        &self,
        command: CommitAcceptedEventCommand,
    ) -> ServiceResult<CommitAcceptedEventResult>;

    async fn commit_accepted_event_batch(
        &self,
        command: CommitAcceptedEventBatchCommand,
    ) -> ServiceResult<CommitAcceptedEventResult>;
}

impl EventService {
    pub fn new(commits: Arc<dyn EventCommitPort>) -> Self {
        Self { commits }
    }

    pub async fn commit_accepted_event(
        &self,
        command: CommitAcceptedEventCommand,
    ) -> ServiceResult<CommitAcceptedEventResult> {
        self.commits.commit_accepted_event(command).await
    }

    pub async fn commit_accepted_event_batch(
        &self,
        command: CommitAcceptedEventBatchCommand,
    ) -> ServiceResult<CommitAcceptedEventResult> {
        self.commits.commit_accepted_event_batch(command).await
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;

    use super::*;

    fn causal_record(
        suffix: u32,
        digest_suffix: u32,
        prev_refs: &[u32],
        causal_refs: &[u32],
        payload: Value,
    ) -> AcceptedEvent {
        let event_id = |value: u32| {
            arkret_identifiers::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                arkret_canonical::sha256_bytes(value.to_be_bytes()),
            )
            .to_string()
        };
        let mut envelope = serde_json::json!({
            "prev_refs": prev_refs.iter().map(|value| event_id(*value)).collect::<Vec<_>>(),
            "payload": payload,
        });
        if !causal_refs.is_empty() {
            envelope.as_object_mut().unwrap().insert(
                "causal_refs".to_owned(),
                serde_json::json!(
                    causal_refs
                        .iter()
                        .map(|value| format!("sha256:{value:064x}"))
                        .collect::<Vec<_>>()
                ),
            );
        }
        AcceptedEvent {
            event_id: event_id(suffix),
            actor_id: "ak:did_core:webvh:z6mkalice".to_owned(),
            realm_id: Some("ak:realm:ATp5qI_DaGqeL1spvchnU-p10lfIfsboDfYyWaObd1Y6".to_owned()),
            kind: arkret_wire::EventKind::MessageCreate.as_str().to_owned(),
            schema_id: "ak.schema.message.v1".to_owned(),
            digest_suite: arkret_canonical::DigestSuite::Sha256,
            canonical_digest: format!("sha256:{digest_suffix:064x}"),
            canonical_bytes: Vec::new(),
            envelope,
            received_at: Utc::now(),
        }
    }

    #[test]
    fn read_cursor_relation_follows_event_edges_not_hlc() {
        let records = vec![
            causal_record(1, 1, &[], &[], serde_json::json!({})),
            causal_record(2, 2, &[1], &[], serde_json::json!({})),
        ];
        assert_eq!(
            read_cursor_causal_relation(
                &records,
                records[0].event_id.as_str(),
                records[1].event_id.as_str(),
            ),
            ReadCursorCausalRelation::CandidateDominatesCurrent
        );
        assert_eq!(
            read_cursor_causal_relation(
                &records,
                records[1].event_id.as_str(),
                records[0].event_id.as_str(),
            ),
            ReadCursorCausalRelation::CurrentDominatesCandidate
        );
    }

    #[test]
    fn canonical_depths_cover_selected_closure_and_reject_missing_or_cyclic_edges() {
        let root = causal_record(1, 1, &[], &[], serde_json::json!({}));
        let root_message = root.event_id.replacen("ak:event:", "ak:message:", 1);
        let reply = causal_record(
            2,
            2,
            &[],
            &[],
            serde_json::json!({"reply_to_id": root_message}),
        );
        let child = causal_record(3, 3, &[2], &[], serde_json::json!({}));
        let irrelevant_missing = causal_record(4, 4, &[99], &[], serde_json::json!({}));
        let roots = BTreeSet::from([child.event_id.clone()]);
        let records = vec![
            root.clone(),
            reply.clone(),
            child.clone(),
            irrelevant_missing,
        ];
        let depths = canonical_event_depths(&records, &roots).unwrap();
        assert_eq!(depths[&root.event_id], 0);
        assert_eq!(depths[&reply.event_id], 1);
        assert_eq!(depths[&child.event_id], 2);
        assert!(canonical_event_depths(&records[1..], &roots).is_err());
        let cycle = vec![causal_record(1, 1, &[2], &[], serde_json::json!({})), reply];
        assert!(canonical_event_depths(&cycle, &BTreeSet::from([root.event_id])).is_err());
    }

    #[test]
    fn read_cursor_relation_resolves_digest_and_message_edges() {
        let first = causal_record(
            1,
            1,
            &[],
            &[],
            serde_json::json!({
                "message_id": "ak:message:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5"
            }),
        );
        let by_digest = causal_record(2, 2, &[], &[1], serde_json::json!({}));
        // Replies are Relations, not a payload member: `replies_to` is not
        // registered anywhere. The registered cross-object carrier is
        // `target_ref`, which resolves as a predecessor edge when it names a
        // Message or Event.
        let reply = causal_record(
            3,
            3,
            &[],
            &[],
            serde_json::json!({
                "target_ref": "ak:message:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5"
            }),
        );
        let records = vec![first, by_digest, reply];
        for candidate in [&records[1], &records[2]] {
            assert_eq!(
                read_cursor_causal_relation(
                    &records,
                    records[0].event_id.as_str(),
                    candidate.event_id.as_str(),
                ),
                ReadCursorCausalRelation::CandidateDominatesCurrent
            );
        }
    }

    #[test]
    fn read_cursor_relation_requires_complete_closure_for_concurrency() {
        let complete = vec![
            causal_record(1, 1, &[], &[], serde_json::json!({})),
            causal_record(2, 2, &[], &[], serde_json::json!({})),
        ];
        assert_eq!(
            read_cursor_causal_relation(
                &complete,
                complete[0].event_id.as_str(),
                complete[1].event_id.as_str(),
            ),
            ReadCursorCausalRelation::Concurrent
        );

        let incomplete = vec![
            causal_record(1, 1, &[99], &[], serde_json::json!({})),
            causal_record(2, 2, &[], &[], serde_json::json!({})),
        ];
        assert_eq!(
            read_cursor_causal_relation(
                &incomplete,
                incomplete[0].event_id.as_str(),
                incomplete[1].event_id.as_str(),
            ),
            ReadCursorCausalRelation::Undecidable
        );
    }

    struct RecordingCommitter;

    #[async_trait]
    impl EventCommitPort for RecordingCommitter {
        async fn commit_accepted_event(
            &self,
            command: CommitAcceptedEventCommand,
        ) -> ServiceResult<CommitAcceptedEventResult> {
            assert_eq!(command.event.kind, "ak.message.create");
            assert_eq!(command.projections.len(), 1);
            assert_eq!(command.deliveries.len(), 1);
            Ok(CommitAcceptedEventResult {
                projections_inserted: 1,
                deliveries_inserted: 1,
            })
        }

        async fn commit_accepted_event_batch(
            &self,
            command: CommitAcceptedEventBatchCommand,
        ) -> ServiceResult<CommitAcceptedEventResult> {
            assert_eq!(command.events.len(), 2);
            assert!(command.applet_record.is_some());
            Ok(CommitAcceptedEventResult {
                projections_inserted: 2,
                deliveries_inserted: 0,
            })
        }
    }

    /// One accepted Event plus the signed commit that ordered it.
    ///
    /// A commit accepts exactly one Event, so the fixture builds the pair
    /// together and keeps the same Realm, stream and Event id on both sides.
    fn authority_commit_fixture(
        event_id: &arkret_identifiers::EventId,
        realm_id: &arkret_identifiers::RealmId,
        now: DateTime<Utc>,
    ) -> soland_storage::AuthorityCommitTransaction {
        let stream_ref = arkret_wire::CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        };
        let authority_ref =
            arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(event_id.clone());
        soland_storage::AuthorityCommitTransaction {
            expected_authority: soland_storage::CurrentRealmAuthority {
                realm_id: realm_id.clone(),
                generation: 0,
                service_id: DidCoreId::new("ak:did_core:web:station.example").unwrap(),
                authority_ref: authority_ref.clone(),
                last_handoff_ref: None,
            },
            event: arkret_wire::Event {
                event_id: event_id.clone(),
                kind: arkret_wire::EventKind::MessageCreate,
                realm_id: realm_id.clone(),
                scope_ref: arkret_wire::ScopeRef::Realm {
                    realm_id: realm_id.clone(),
                },
                actor_id: arkret_wire::ActorId::account(accountability_account(
                    "ak:did_core:web:alice.example",
                )),
                executed_by: None,
                authorization_ref: None,
                applet_id: None,
                external_ref: None,
                created_at: now,
                refs: Vec::new(),
                payload: BTreeMap::new(),
                producer_proof: None,
            },
            commit: arkret_wire::RealmCommit {
                commit_id: arkret_wire::RealmCommitId::from_digest([0x32; 32]),
                realm_id: realm_id.clone(),
                stream_ref,
                stream_position: 0,
                previous_commit_ref: None,
                event_ref: event_id.clone(),
                governance_generation: 0,
                authority_ref,
                committed_at: now,
                signature: arkret_wire::DetachedObjectSignature {
                    context: arkret_wire::DetachedSignatureContext::RealmCommit,
                    signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
                    verification_method: arkret_wire::DidUrl::new(
                        "did:web:station.example#authority",
                    )
                    .unwrap(),
                    signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "3".repeat(64)))
                        .unwrap(),
                    created_at: now,
                    sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl".to_owned()).unwrap(),
                },
            },
            mls_state: None,
            welcomes: Vec::new(),
        }
    }

    #[tokio::test]
    async fn accepted_event_command_is_committed_through_one_port() {
        let now = Utc::now();
        let event_id = arkret_identifiers::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x31; 32],
        );
        let realm_id = arkret_identifiers::RealmId::from_event_id(&event_id);
        let authority_commit = authority_commit_fixture(&event_id, &realm_id, now);
        let event_id = event_id.to_string();
        let realm_id = realm_id.to_string();
        let service = EventService::new(Arc::new(RecordingCommitter));
        let result = service
            .commit_accepted_event(CommitAcceptedEventCommand {
                authority_commit,
                device_pairing_authorization: None,
                contact_projection: None,
                agent_draft_pending_intent: None,
                actor_private_account_data: None,
                consent_projection: None,
                event: AcceptedEvent {
                    event_id: event_id.clone(),
                    actor_id: "ak:did_core:web:alice.example".to_owned(),
                    realm_id: Some(realm_id.clone()),
                    kind: "ak.message.create".to_owned(),
                    schema_id: "arkret://events/message/create/v1".to_owned(),
                    digest_suite: arkret_canonical::DigestSuite::Sha256,
                    canonical_digest: "sha256:test".to_owned(),
                    canonical_bytes: vec![1],
                    envelope: serde_json::json!({}),
                    received_at: now,
                },
                device_revocation_transition: None,
                device_revocation_gate: None,
                projections: vec![ProjectedEvent {
                    event_id,
                    realm_id,
                    event_kind: arkret_wire::EventKind::MessageCreate,
                    operation_kind: "create".to_owned(),
                    operation_id: None,
                    sender: Some("did:web:alice.example".to_owned()),
                    payload: serde_json::json!({}),
                    created_at: now,
                    received_at: now,
                }],
                idempotency: None,
                deliveries: vec![FederationDeliveryRecord {
                    id: "delivery:test".to_owned(),
                    peer_id: arkret_wire::DidCoreId::new("ak:did_core:web:peer.example")
                        .expect("peer service id"),
                    peer_url: Some("https://peer.example".to_owned()),
                    endpoint: "/_arkret/peer/events".to_owned(),
                    idempotency_key: "event:test".to_owned(),
                    payload_json: "{}".to_owned(),
                    coalescing_key: None,
                    coalescing_position: None,
                    realm_fanout: None,
                    created_at: now.timestamp(),
                }],
            })
            .await
            .expect("commit accepted event");
        assert_eq!(result.projections_inserted, 1);
        assert_eq!(result.deliveries_inserted, 1);
    }

    fn accountability_account(principal: &str) -> arkret_wire::AccountId {
        arkret_wire::AccountId::new(
            DidCoreId::new(principal).unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        )
    }

    fn accountability_event(
        event_id: &str,
        grant_status: &str,
        received_at: DateTime<Utc>,
    ) -> AcceptedEvent {
        accountability_event_with_scope(
            event_id,
            grant_status,
            serde_json::json!("agent_operator"),
            received_at,
        )
    }

    fn accountability_event_with_scope(
        event_id: &str,
        grant_status: &str,
        accountability_scope: Value,
        received_at: DateTime<Utc>,
    ) -> AcceptedEvent {
        let mut payload = AccountabilityGrantPayload {
            schema: AccountabilityGrantPayload::SCHEMA.to_owned(),
            issuer_id: DidCoreId::new("ak:did_core:web:controller.example").unwrap(),
            subject_id: DidCoreId::new("ak:did_core:web:agent.example").unwrap(),
            accountability_scope: serde_json::from_value(accountability_scope).unwrap(),
            not_before: "2026-01-01T00:00:00Z".parse().unwrap(),
            expires_at: Some("2099-01-01T00:00:00Z".parse().unwrap()),
            grant_status: serde_json::from_value(serde_json::json!(grant_status)).unwrap(),
            proof: arkret_wire::PayloadProof {
                kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
                verification_method: arkret_wire::DidUrl::new("did:web:controller.example#key-1")
                    .unwrap(),
                payload_digest: arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64)))
                    .unwrap(),
                created_at: "2026-01-01T00:00:00Z".parse().unwrap(),
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: String::new(),
            },
        };
        payload.proof.payload_digest = payload.payload_digest().unwrap();
        payload.proof.jws = arkret_signatures::Ed25519DetachedJwsSigner::from_seed(
            [17; 32],
            payload.proof.verification_method.as_str(),
        )
        .sign_detached_jws(&payload.canonical_proof_binding_bytes().unwrap());
        payload.proof.validate_production().unwrap();
        AcceptedEvent {
            event_id: event_id.to_owned(),
            actor_id: arkret_wire::ActorId::account(accountability_account(
                "ak:did_core:web:controller.example",
            ))
            .to_string(),
            realm_id: Some("ak:realm:AXqIXbu56hFXteZXtkBsqJxy_puV4mhSv1U0ZkUldxAL".to_owned()),
            kind: "ak.identity.accountability_grant".to_owned(),
            schema_id: "ak.schema.event.v1".to_owned(),
            digest_suite: arkret_canonical::DigestSuite::Sha256,
            canonical_digest: format!("sha256:{}", event_id),
            canonical_bytes: Vec::new(),
            envelope: serde_json::json!({
                "actor_id": arkret_wire::ActorId::account(accountability_account(
                    "ak:did_core:web:controller.example",
                )),
                "executed_by": arkret_wire::ActorId::account(accountability_account(
                    "ak:did_core:web:controller.example",
                )),
                "payload": payload
            }),
            received_at,
        }
    }

    #[test]
    fn active_agent_accountability_uses_latest_matching_grant_lifecycle() {
        let accepted_at = DateTime::parse_from_rfc3339("2027-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let original = accountability_event(
            "ak:event:AR-4MwpAcHt7pmjO-Cab9s-33ymPZefvcpl666_jGxiY",
            "active",
            accepted_at - chrono::Duration::minutes(2),
        );
        let query = ActiveAgentAccountabilityQuery {
            accountability_event_id: original.event_id.clone(),
            controller_account_id: accountability_account("ak:did_core:web:controller.example"),
            agent_account_id: accountability_account("ak:did_core:web:agent.example"),
            accepted_at,
        };
        assert!(active_agent_accountability(
            &original,
            std::slice::from_ref(&original),
            &query
        ));

        let revoked = accountability_event(
            "ak:event:AUqzNZlfuL-7z087TbZhKOdYyKUNPAa2o_neyoFRh3o2",
            "revoked",
            accepted_at - chrono::Duration::minutes(1),
        );
        assert!(!active_agent_accountability(
            &original,
            &[original.clone(), revoked],
            &query
        ));

        let wrong_controller = ActiveAgentAccountabilityQuery {
            controller_account_id: accountability_account("ak:did_core:web:other.example"),
            ..query.clone()
        };
        assert!(!active_agent_accountability(
            &original,
            std::slice::from_ref(&original),
            &wrong_controller
        ));

        let mut foreign = query.clone();
        foreign.controller_account_id.station_id =
            DidCoreId::new("ak:did_core:web:other-station.example").unwrap();
        foreign.agent_account_id.station_id = foreign.controller_account_id.station_id.clone();
        assert!(!active_agent_accountability(
            &original,
            std::slice::from_ref(&original),
            &foreign,
        ));
        let mut wrong_executor = original.clone();
        wrong_executor.envelope["executed_by"] =
            serde_json::to_value(arkret_wire::ActorId::account(foreign.controller_account_id))
                .unwrap();
        assert!(!active_agent_accountability(
            &wrong_executor,
            std::slice::from_ref(&wrong_executor),
            &query,
        ));
        for invalid in [
            serde_json::json!("ak:did_core:web:controller.example"),
            serde_json::Value::Null,
        ] {
            let mut malformed = original.clone();
            malformed.envelope["executed_by"] = invalid;
            assert!(accepted_event_executor(&malformed).is_none());
        }
        let mut mismatched_metadata = original.clone();
        mismatched_metadata.actor_id = "ak:did_core:web:controller.example".to_owned();
        assert!(accepted_event_executor(&mismatched_metadata).is_none());
        let mut no_executor = original.clone();
        no_executor
            .envelope
            .as_object_mut()
            .unwrap()
            .remove("executed_by");
        assert_eq!(
            accepted_event_executor(&no_executor),
            Some(arkret_wire::ActorId::account(
                query.controller_account_id.clone()
            )),
        );
    }

    #[test]
    fn accountability_exact_set_lifecycle_and_projection_are_order_independent() {
        let accepted_at = DateTime::parse_from_rfc3339("2027-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let superset = accountability_event_with_scope(
            "ak:event:AWuZMGvx81gljFzdfo91GdpWgxDdUqYNw9iNo8O1vNA1",
            "active",
            serde_json::json!(["employment", "agent_operator"]),
            accepted_at - chrono::Duration::minutes(5),
        );
        let singleton = accountability_event_with_scope(
            "ak:event:AU9DZnJIDT2wyYXkcOaxGWwgzqUNfXVjwSMWvYrUjaHp",
            "active",
            serde_json::json!("contracted_service"),
            accepted_at - chrono::Duration::minutes(4),
        );
        let reordered_revoke = accountability_event_with_scope(
            "ak:event:AXknLJ0H-GIpZ65_VZ9tb638gg0xRIXmCgbGov3x_ApA",
            "revoked",
            serde_json::json!(["agent_operator", "employment"]),
            accepted_at - chrono::Duration::minutes(3),
        );
        let events = [superset.clone(), singleton, reordered_revoke];
        let query = ActiveAgentAccountabilityQuery {
            accountability_event_id: superset.event_id.clone(),
            controller_account_id: accountability_account("ak:did_core:web:controller.example"),
            agent_account_id: accountability_account("ak:did_core:web:agent.example"),
            accepted_at,
        };
        assert!(!active_agent_accountability(&superset, &events, &query));
        assert_eq!(
            active_accountability_scopes(
                &events,
                superset.realm_id.as_deref(),
                &query.controller_account_id,
                query.agent_account_id.principal_id.as_str(),
                accepted_at,
            ),
            BTreeSet::from([AccountabilityScopeKind::ContractedService])
        );
    }

    #[test]
    fn accountability_subset_revoke_does_not_change_active_superset() {
        let accepted_at = DateTime::parse_from_rfc3339("2027-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let superset = accountability_event_with_scope(
            "ak:event:Acapa6RU80HiheFa2k-I6_Kninlrm7FBWLC_EvO82g56",
            "active",
            serde_json::json!(["employment", "agent_operator"]),
            accepted_at - chrono::Duration::minutes(3),
        );
        let subset_revoke = accountability_event_with_scope(
            "ak:event:AVq1LpKIoEWFf3axTV6jqi4qRyX5y0PRTrCVtTE9L_V4",
            "revoked",
            serde_json::json!("employment"),
            accepted_at - chrono::Duration::minutes(2),
        );
        let events = [superset.clone(), subset_revoke];
        let query = ActiveAgentAccountabilityQuery {
            accountability_event_id: superset.event_id.clone(),
            controller_account_id: accountability_account("ak:did_core:web:controller.example"),
            agent_account_id: accountability_account("ak:did_core:web:agent.example"),
            accepted_at,
        };
        assert!(active_agent_accountability(&superset, &events, &query));
        assert_eq!(
            active_accountability_scopes(
                &events,
                superset.realm_id.as_deref(),
                &query.controller_account_id,
                query.agent_account_id.principal_id.as_str(),
                accepted_at,
            ),
            BTreeSet::from([
                AccountabilityScopeKind::AgentOperator,
                AccountabilityScopeKind::Employment,
            ])
        );
    }
}
