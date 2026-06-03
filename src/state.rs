use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use cokret_sdk::identity::CompositeDidResolver;
use cokret_sdk::{Did, RealmId};
use ed25519_dalek::SigningKey;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::broadcast;

use crate::authz::AuthzEngine;
use crate::config::{AnchorerSigningKeyOrigin, AppConfig};
use crate::db::Db;
use crate::hlc::ServerHlc;
use crate::object_storage::{ObjectStorage, build_object_storage};
use crate::persistence::{MemoryPersistenceStore, PersistenceStore, PgPersistenceStore};
use crate::reducer::ProjectionState;
use crate::verified_profiles::VerifiedProfileDescriptor;

const MAX_SUBSCRIBE_RECONNECT_WINDOW_MS: u64 = 86_400_000;

// `did_resolver_chain.rs` lives at `src/did_resolver_chain.rs`; declare it as
// a submodule of `state` so `AppState::new` can construct the resolver chain
// locally and re-export it as `crate::state::did_resolver_chain`.
#[path = "did_resolver_chain.rs"]
pub mod did_resolver_chain;

/// broadcast payload for the
/// [`AppState::event_broadcast`] channel. Subscribers filter by
/// `realm_id` first, then dispatch on `kind` to produce the right
/// NDJSON frame.
///
/// added control-frame variants alongside the original `Event`
/// (mid-stream control frames per spec):
///   - `EpochRotation` — emitted when `cx.component.mls.epoch.v1` cell changes (E2EE epoch shift;
///     clients MUST re-fetch keys)
///   - `Frontier` — anchor frontier advanced (Snapshot of cursor / state_root after
///     `apply_anchor`); clients use this as a resync waypoint
///   - `ResyncRequired` — server detected per-subscriber drift; client MUST drop local cache and
///     re-subscribe with `from=null`
///   - `Unauthorized` — subscriber's session token revoked / expired mid-stream; client MUST close
///     + re-auth
#[derive(Clone, Debug)]
pub struct EventNotification {
    pub realm_id: String,
    pub kind: EventNotificationKind,
}

#[derive(Clone, Debug)]
pub enum EventNotificationKind {
    /// Ordinary projection event (one `ck.message.create` etc.).
    Event {
        /// Stable cursor for the event — typically the canonical
        /// `event_id`. Clients use as resume position.
        cursor: String,
        /// Projection-event JSON (same shape as `projection_event_json`).
        event_payload: Value,
    },
    /// MLS epoch shift detected on `cx.component.mls.epoch.v1` cell.
    EpochRotation {
        /// Old epoch value (the previous CellState::Value if known).
        previous_epoch: Option<Value>,
        /// New epoch value (current CellState::Value after the
        /// triggering apply_anchor).
        new_epoch: Value,
    },
    /// Anchor frontier advanced. Emitted post-`apply_anchor` so clients
    /// can update their resume cursor without waiting for the next event.
    Frontier {
        /// `apply_anchor`'s `post_state_root` (canonical Merkle).
        state_root: String,
        /// The Anchor's id, useful for clients tracking Anchor DAG.
        anchor_id: String,
    },
    /// Per-subscriber drift / corrupted-cursor signal. Clients SHOULD
    /// drop local cache + restart subscription with no `from`.
    ResyncRequired {
        reason: String,
        reconnect_after_ms: Option<u64>,
    },
    /// Session token invalidated mid-stream — client MUST close.
    Unauthorized { reason: String },
}

impl EventNotification {
    pub fn event(realm_id: String, cursor: String, event_payload: Value) -> Self {
        Self {
            realm_id,
            kind: EventNotificationKind::Event {
                cursor,
                event_payload,
            },
        }
    }

    pub fn epoch_rotation(
        realm_id: String,
        previous_epoch: Option<Value>,
        new_epoch: Value,
    ) -> Self {
        Self {
            realm_id,
            kind: EventNotificationKind::EpochRotation {
                previous_epoch,
                new_epoch,
            },
        }
    }

    pub fn frontier(realm_id: String, anchor_id: String, state_root: String) -> Self {
        Self {
            realm_id,
            kind: EventNotificationKind::Frontier {
                state_root,
                anchor_id,
            },
        }
    }
}

/// In-process reconnect gate for `ck.events.subscribe` and
/// `ck.account.subscribe`. Keys are operation + caller identity + selector
/// scope, and values are the earliest accepted reconnect time.
#[derive(Clone, Debug, Default)]
pub struct SubscribeReconnectGate {
    deadlines: BTreeMap<String, DateTime<Utc>>,
}

impl SubscribeReconnectGate {
    pub fn retry_after_ms(&mut self, key: &str, now: DateTime<Utc>) -> Option<u64> {
        self.prune_expired(now);
        let deadline = self.deadlines.get(key)?;
        if *deadline <= now {
            self.deadlines.remove(key);
            return None;
        }
        Some((*deadline - now).num_milliseconds().max(1) as u64)
    }

    pub fn arm(&mut self, key: impl Into<String>, now: DateTime<Utc>, delay_ms: u64) {
        if delay_ms == 0 {
            return;
        }
        let clamped_ms = delay_ms.min(MAX_SUBSCRIBE_RECONNECT_WINDOW_MS) as i64;
        self.deadlines
            .insert(key.into(), now + ChronoDuration::milliseconds(clamped_ms));
        self.prune_expired(now);
    }

    fn prune_expired(&mut self, now: DateTime<Utc>) {
        self.deadlines.retain(|_, deadline| *deadline > now);
    }
}

#[cfg(test)]
mod subscribe_reconnect_gate_tests {
    use super::*;

    #[test]
    fn reports_remaining_window_and_expires() {
        let mut gate = SubscribeReconnectGate::default();
        let now = Utc::now();
        gate.arm("ck.events.subscribe|alice|realm-a", now, 10_000);

        let retry_after = gate
            .retry_after_ms(
                "ck.events.subscribe|alice|realm-a",
                now + ChronoDuration::milliseconds(2_500),
            )
            .expect("cooldown active");
        assert!((7_400..=7_500).contains(&retry_after));

        assert!(
            gate.retry_after_ms(
                "ck.events.subscribe|alice|realm-a",
                now + ChronoDuration::milliseconds(10_000),
            )
            .is_none()
        );
    }
}

#[derive(Clone, Debug, Default)]
pub struct RealmDirectoryQuery {
    pub text: Option<String>,
    pub tags: BTreeSet<String>,
    pub members: BTreeSet<Did>,
    pub public_only: bool,
    pub limit: Option<usize>,
}

/// Searchable Realm directory entry. This intentionally replaces the SDK
/// `SpaceSearchEntry` in soland because Realm, not Space, owns membership,
/// discovery, history visibility and plaintext-service policy.
#[derive(
    Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, salvo::oapi::ToSchema,
)]
pub struct RealmDirectoryEntry {
    pub realm_id: RealmId,
    pub name: String,
    pub description: Option<String>,
    pub tags: BTreeSet<String>,
    pub members: BTreeSet<Did>,
    pub public: bool,
    pub category: Option<String>,
}

impl RealmDirectoryEntry {
    pub fn new(realm_id: RealmId, name: impl Into<String>) -> Self {
        Self {
            realm_id,
            name: name.into(),
            description: None,
            tags: BTreeSet::new(),
            members: BTreeSet::new(),
            public: false,
            category: None,
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

    /// Iterate `(realm_id, entry)` pairs. Used by the erasure cascade
    /// (`account.rs::remove_realm_memberships_for_actor`) to enumerate
    /// every realm the erased actor was a member of.
    pub fn entries_iter(&self) -> impl Iterator<Item = (&RealmId, &RealmDirectoryEntry)> {
        self.entries.iter()
    }

    pub fn search_by_text(&self, query: &str) -> Vec<&RealmDirectoryEntry> {
        let query = query.to_lowercase();
        self.entries
            .values()
            .filter(|entry| realm_directory_text(entry).contains(&query))
            .collect()
    }

    pub fn search_by_tag(&self, tag: &str) -> Vec<&RealmDirectoryEntry> {
        self.entries
            .values()
            .filter(|entry| entry.tags.contains(tag))
            .collect()
    }

    pub fn search_by_member(&self, member: &Did) -> Vec<&RealmDirectoryEntry> {
        self.entries
            .values()
            .filter(|entry| entry.members.contains(member))
            .collect()
    }

    pub fn search(&self, query: RealmDirectoryQuery) -> Vec<&RealmDirectoryEntry> {
        let mut scored: Vec<_> = self
            .entries
            .values()
            .filter(|entry| !query.public_only || entry.public)
            .filter(|entry| {
                query
                    .text
                    .as_ref()
                    .map(|text| realm_directory_text(entry).contains(&text.to_lowercase()))
                    .unwrap_or(true)
            })
            .filter(|entry| query.tags.iter().all(|tag| entry.tags.contains(tag)))
            .filter(|entry| {
                query
                    .members
                    .iter()
                    .all(|member| entry.members.contains(member))
            })
            .map(|entry| (realm_directory_score(entry, &query), entry))
            .collect();

        scored.sort_by(|(left_score, left), (right_score, right)| {
            right_score
                .cmp(left_score)
                .then_with(|| left.name.cmp(&right.name))
        });

        let mut results: Vec<_> = scored.into_iter().map(|(_, entry)| entry).collect();
        if let Some(limit) = query.limit {
            results.truncate(limit);
        }
        results
    }
}

fn realm_directory_text(entry: &RealmDirectoryEntry) -> String {
    format!(
        "{} {} {}",
        entry.name,
        entry.description.as_deref().unwrap_or_default(),
        entry.tags.iter().cloned().collect::<Vec<_>>().join(" ")
    )
    .to_lowercase()
}

fn realm_directory_score(entry: &RealmDirectoryEntry, query: &RealmDirectoryQuery) -> usize {
    let mut score = 0;
    if let Some(text) = &query.text {
        let text = text.to_lowercase();
        if entry.name.to_lowercase().contains(&text) {
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

/// R3.1/R3.2 (cokret-spec @ b56cab1) — Realm-scoped MemberIdentity event
/// registry. Stores every accepted `ck.member.identity.update` event by
/// `(realm_id, actor_id, segment)`, computes the current effective set
/// per the SDK helper `effective_identity_events`, and materializes both
/// R3.2 digests: the `expected_state_digest` guard
/// (`member_identity_effective_set_digest`, includes `segment`) and the
/// roster `member_display_state_digest`. The reducer
/// (`reducer::apply_member_identity_update`) consults the guard for the
/// optimistic-concurrency check (`expected_state_digest`) and writes
/// accepted events back; the sync roster
/// (`sync::roster_members_for_realm`) reads the resulting snapshot to
/// emit `MemberRosterEntry`.
///
/// Storage is in-memory for now; durable persistence (alongside the
/// other event-log surfaces) lands when the MID schema migration ships.
/// Plaintext Ed25519 `MemberIdentityProof` verification runs on the
/// event-ingest path before records reach this registry. Encrypted
/// carriers and non-Ed25519 proof algorithms are currently refused
/// fail-closed rather than stored after shape-only validation. Reducer-
/// shape validation (segment whitelist, replacement-digest binding,
/// cross-(realm,actor, segment) guard) IS real per MID-2.
#[derive(Clone, Debug, Default)]
pub struct MemberIdentityRegistry {
    /// All accepted events, keyed by `event_id`.
    events: BTreeMap<String, MemberIdentityEventRecord>,
    /// Index from `(realm_id, actor_id, segment)` → event_ids that
    /// landed against that cell subject, in arrival order.
    by_subject: BTreeMap<MemberIdentitySubjectKey, Vec<String>>,
    /// Local handle-claim evidence cache keyed by claim `subject`.
    /// Sources are deliberately local-only: directory-issued signed claims
    /// and handle-claim envelopes carried by accepted identity events.
    handle_claims_by_subject: BTreeMap<String, Vec<HandleClaimEvidenceRecord>>,
}

/// Cell subject key for [`MemberIdentityRegistry`]. Mirrors the
/// composite `(payload.realm_id, payload.actor_id, payload.segment)` cell
/// subject from `event-kind-registry.json`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MemberIdentitySubjectKey {
    pub realm_id: String,
    pub actor_id: String,
    pub segment: String,
}

/// One stored `ck.member.identity.update` event.
#[derive(Clone, Debug)]
pub struct MemberIdentityEventRecord {
    pub event_id: String,
    pub subject: MemberIdentitySubjectKey,
    /// SHA-256 over RFC 8785 JCS canonical JSON of the full
    /// `payload.identity_payload` carrier object (the value goes into
    /// any subsequent event's `payload.replaces[].payload_digest`).
    pub payload_digest: String,
    /// `payload.replaces[]` references as observed on the wire. The
    /// reducer keeps the raw list so the effective-set filter can match
    /// each edge's `payload_digest` against the referenced event's stored
    /// `payload_digest` at projection time (mismatched / cross-subject
    /// references are dropped as no-op edges per MID-2).
    pub replaces: Vec<MemberIdentityReplacementEdge>,
    /// Original Event envelope as received. MID-5: soland MUST store the
    /// envelope verbatim; no query-time re-encryption, no projection
    /// rewrite.
    pub raw_event: Value,
}

#[derive(Clone, Debug)]
pub struct HandleClaimEvidenceRecord {
    pub digest: String,
    pub subject_id: String,
    pub issuer: String,
    pub issuer_service_did: Option<String>,
    pub audience: Option<String>,
    pub binding_state: String,
    pub visibility: Option<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub revoked: bool,
    pub envelope: Value,
}

#[derive(Clone, Debug)]
pub struct HandleClaimDigestInput {
    pub claim_digest: String,
    pub binding_state: String,
    pub expires_at: Option<String>,
}

/// One replacement edge resolved from `payload.replaces[]`.
#[derive(Clone, Debug)]
pub struct MemberIdentityReplacementEdge {
    pub event_id: String,
    pub payload_digest: String,
}

/// One entry of the effective `(event_id, segment, payload_digest)` set,
/// surfaced from [`MemberIdentitySnapshot`] so callers (the reducer's
/// `expected_state_digest` guard and the sync roster's
/// `member_display_state_digest`) can recompute the R3.2 digests via the
/// SDK helpers `member_identity_effective_set_digest` /
/// `member_display_state_digest`.
#[derive(Clone, Debug)]
pub struct EffectiveIdentityEntry {
    pub event_id: String,
    pub segment: String,
    pub payload_digest: String,
}

/// Per-`(realm_id, actor_id)` snapshot derived on demand by
/// [`MemberIdentityRegistry::snapshot_for_actor`]. Drives the sync
/// roster projection (`SYNC-MEM-1..3`, R3.2 ROST-SOL-1..3).
///
/// MIU-SOL-4 (R3.2): the effective set is exposed verbatim as
/// `identity_event_ids` / `identity_events` / `effective_entries` with NO
/// last-writer-wins collapse — a multi-valued effective set (concurrent
/// un-replaced writes) is returned as-is so the roster lists every
/// effective event.
#[derive(Clone, Debug, Default)]
pub struct MemberIdentitySnapshot {
    /// Effective event ids per the replacement-edge filter, sorted by
    /// `(segment, event_id)`. Matches the wire-side `identity_event_ids[]`.
    pub identity_event_ids: Vec<String>,
    /// Effective `(event_id, segment, payload_digest)` triples, sorted by
    /// `(segment, event_id)`. Drives the R3.2 digest helpers.
    pub effective_entries: Vec<EffectiveIdentityEntry>,
    /// R3.2 ROST-SOL-1 — roster display cache key
    /// (`member_display_state_digest`). `sha256:<hex>` over the effective
    /// identity-event set folded with the currently visible handle-claim
    /// digest set. Equals the SDK `member_display_state_digest` helper.
    pub member_display_state_digest: Option<String>,
    /// R3.2 ROST-SOL-2 — disclosed principal / holder `subject_id`, read
    /// from the effective plaintext `MemberIdentity` carrier when present.
    /// `None` for an encrypted-only effective set.
    pub subject_id: Option<String>,
    /// Original Event envelopes for the effective set. Used by
    /// `SYNC-MEM-3` (inline events when the client lacks them).
    pub identity_events: Vec<Value>,
}

impl MemberIdentityRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of stored events. Used by debug surfaces.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Look up by event_id.
    pub fn get(&self, event_id: &str) -> Option<&MemberIdentityEventRecord> {
        self.events.get(event_id)
    }

    /// Insert an accepted event. Replaces any prior entry under the same
    /// `event_id` (idempotent re-projection on replay).
    pub fn insert(&mut self, record: MemberIdentityEventRecord) {
        let key = record.subject.clone();
        let event_id = record.event_id.clone();
        let bucket = self.by_subject.entry(key).or_default();
        if !bucket.iter().any(|id| id == &event_id) {
            bucket.push(event_id.clone());
        }
        self.events.insert(event_id, record);
    }

    /// Insert one canonical signed handle-claim envelope into the local
    /// evidence cache. The digest is always SHA-256 over RFC 8785 canonical
    /// JSON of the full envelope as stored, including proofs/signatures.
    pub fn upsert_handle_claim_envelope(&mut self, envelope: Value) -> Option<String> {
        let subject_id = envelope.get("subject")?.as_str()?.to_owned();
        let issuer = envelope.get("issuer")?.as_str()?.to_owned();
        let digest = canonical_digest(&envelope, "", subject_id.as_str(), "handle_claim_digest")?;
        let binding_state = envelope
            .get("binding_state")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned();
        let audience = envelope
            .get("audience")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let issuer_service_did = envelope
            .get("issuer_service_did")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let visibility = envelope
            .get("visibility")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let expires_at = envelope
            .get("expires_at")
            .and_then(Value::as_str)
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
            .map(|value| value.with_timezone(&chrono::Utc));
        let revoked = envelope
            .get("revoked")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || envelope.get("revoked_at").is_some()
            || binding_state == "revoked";
        let record = HandleClaimEvidenceRecord {
            digest: digest.clone(),
            subject_id: subject_id.clone(),
            issuer,
            issuer_service_did,
            audience,
            binding_state,
            visibility,
            expires_at,
            revoked,
            envelope,
        };
        let bucket = self.handle_claims_by_subject.entry(subject_id).or_default();
        if let Some(existing) = bucket.iter_mut().find(|existing| existing.digest == digest) {
            *existing = record;
        } else {
            bucket.push(record);
            bucket.sort_by(|a, b| a.digest.cmp(&b.digest));
        }
        Some(digest)
    }

    pub fn upsert_handle_claims_from_identity_payload(&mut self, identity_payload: &Value) {
        for claim in handle_claim_envelopes_in_identity_payload(identity_payload) {
            let _ = self.upsert_handle_claim_envelope(claim.clone());
        }
    }

    pub fn handle_claims_for_subject(&self, subject_id: &str) -> Vec<HandleClaimEvidenceRecord> {
        self.handle_claims_by_subject
            .get(subject_id)
            .cloned()
            .unwrap_or_default()
    }

    /// MIU-SOL-3 (R3.2) — compute the current writer-observed
    /// effective-set digest for `(realm_id, actor_id)` across all stored
    /// segments. This is the value an incoming event's
    /// `expected_state_digest` MUST equal BEFORE it lands (optimistic
    /// concurrency guard). Returns `None` if no events are stored.
    ///
    /// Uses the SDK `member_identity_effective_set_digest` formula
    /// `sha256(JCS({realm_id, actor_id, segment, effective_events:
    /// [{event_id, segment, payload_digest}]}))` — note this INCLUDES
    /// `segment` and is distinct from the roster
    /// `member_display_state_digest`.
    pub fn current_state_digest_for_actor(&self, realm_id: &str, actor_id: &str) -> Option<String> {
        let snapshot = self.snapshot_for_actor(realm_id, actor_id)?;
        effective_set_digest(realm_id, actor_id, &snapshot.effective_entries)
    }

    /// Build a [`MemberIdentitySnapshot`] across all segments under
    /// `(realm_id, actor_id)`. Applies the replacement-edge filter per
    /// MID-2/3, sorts by `(segment, event_id)`, and computes the
    /// projection digest per MID-6.
    pub fn snapshot_for_actor(
        &self,
        realm_id: &str,
        actor_id: &str,
    ) -> Option<MemberIdentitySnapshot> {
        let candidates: Vec<&MemberIdentityEventRecord> = self
            .by_subject
            .iter()
            .filter(|(key, _)| key.realm_id == realm_id && key.actor_id == actor_id)
            .flat_map(|(_, ids)| ids.iter().filter_map(|id| self.events.get(id.as_str())))
            .collect();
        if candidates.is_empty() {
            return None;
        }
        // Drop events that any other valid replacement edge points at —
        // "valid" meaning the edge's `payload_digest` matches the
        // referenced event's stored digest AND the edge sits in the same
        // `(realm_id, actor_id, segment)` cell as the referenced event.
        let by_id: BTreeMap<&str, &MemberIdentityEventRecord> = candidates
            .iter()
            .map(|r| (r.event_id.as_str(), *r))
            .collect();
        let mut replaced = BTreeSet::<String>::new();
        for record in &candidates {
            for edge in &record.replaces {
                let Some(referenced) = by_id.get(edge.event_id.as_str()) else {
                    continue;
                };
                if referenced.subject != record.subject {
                    continue; // cross-cell reference is a no-op edge
                }
                if referenced.payload_digest != edge.payload_digest {
                    continue; // mismatched digest is a no-op edge
                }
                replaced.insert(edge.event_id.clone());
            }
        }
        let mut effective: Vec<&MemberIdentityEventRecord> = candidates
            .into_iter()
            .filter(|r| !replaced.contains(r.event_id.as_str()))
            .collect();
        effective.sort_by(|a, b| {
            a.subject
                .segment
                .cmp(&b.subject.segment)
                .then_with(|| a.event_id.cmp(&b.event_id))
        });

        let effective_entries: Vec<EffectiveIdentityEntry> = effective
            .iter()
            .map(|r| EffectiveIdentityEntry {
                event_id: r.event_id.clone(),
                segment: r.subject.segment.clone(),
                payload_digest: r.payload_digest.clone(),
            })
            .collect();

        // ROST-SOL-2 (R3.2) — read the disclosed `subject_id` from the
        // first effective plaintext `MemberIdentity` carrier. Encrypted
        // carriers do not expose it; `None` then. Disclosure gating
        // (whether to actually emit it on the wire) is enforced at the
        // sync layer per Realm policy.
        let subject_id = effective.iter().find_map(|r| {
            r.raw_event
                .get("payload")
                .and_then(|payload| payload.get("identity_payload"))
                .and_then(|carrier| carrier.get("member_identity"))
                .and_then(|identity| identity.get("subject_id"))
                .and_then(Value::as_str)
                .map(str::to_owned)
        });

        // ROST-SOL-1 (R3.2) — roster `member_display_state_digest`.
        // SHA-256 over RFC 8785 JCS canonical JSON of
        // `{realm_id, actor_id, effective_events:[{event_id, segment,
        // payload_digest}], handle_claims:[{claim_digest, binding_state,
        // expires_at}]}` (effective_events sorted by (segment, event_id),
        // handle_claims sorted by claim_digest). The handle-claim set is
        // empty until the local handle-claim evidence cache is wired
        // (TODO(R3.2.1)); the digest inputs are otherwise stable.
        let member_display_state_digest =
            display_state_digest(realm_id, actor_id, &effective_entries, &[]);

        Some(MemberIdentitySnapshot {
            identity_event_ids: effective.iter().map(|r| r.event_id.clone()).collect(),
            effective_entries,
            member_display_state_digest,
            subject_id,
            identity_events: effective.iter().map(|r| r.raw_event.clone()).collect(),
        })
    }
}

fn handle_claim_envelopes_in_identity_payload(identity_payload: &Value) -> Vec<&Value> {
    let mut out = Vec::new();
    if let Some(claims) = identity_payload
        .get("handle_claims")
        .and_then(Value::as_array)
    {
        out.extend(claims.iter());
    }
    if let Some(claims) = identity_payload
        .get("member_identity")
        .and_then(|member_identity| member_identity.get("handle_claims"))
        .and_then(Value::as_array)
    {
        out.extend(claims.iter());
    }
    out
}

/// JCS-sorted `effective_events` array shared by both R3.2 digest formulas.
/// Each entry is `{event_id, segment, payload_digest}`; the array is sorted
/// by `(segment, event_id)` exactly as the SDK helpers do. Kept as raw JSON
/// (rather than the SDK newtypes) because soland stores `ck:operation:`
/// event ids, which the strict `EventId` `ck:event:` validator would reject —
/// the on-the-wire JCS bytes are identical either way.
fn effective_events_projection(entries: &[EffectiveIdentityEntry]) -> Vec<Value> {
    let mut sorted: Vec<&EffectiveIdentityEntry> = entries.iter().collect();
    sorted.sort_by(|a, b| {
        a.segment
            .cmp(&b.segment)
            .then_with(|| a.event_id.cmp(&b.event_id))
    });
    sorted
        .into_iter()
        .map(|entry| {
            serde_json::json!({
                "event_id": entry.event_id,
                "segment": entry.segment,
                "payload_digest": entry.payload_digest,
            })
        })
        .collect()
}

/// MIU-SOL-3 (R3.2) — `expected_state_digest` writer-observed effective-set
/// digest. SHA-256 over RFC 8785 JCS canonical JSON of
/// `{realm_id, actor_id, segment, effective_events:[{event_id, segment,
/// payload_digest}]}`. Byte-compatible with the SDK
/// `member_identity_effective_set_digest` helper. v1 core declares a single
/// `member_identity` segment.
fn effective_set_digest(
    realm_id: &str,
    actor_id: &str,
    entries: &[EffectiveIdentityEntry],
) -> Option<String> {
    let projection = serde_json::json!({
        "realm_id": realm_id,
        "actor_id": actor_id,
        "segment": "member_identity",
        "effective_events": effective_events_projection(entries),
    });
    canonical_digest(&projection, realm_id, actor_id, "expected_state_digest")
}

/// ROST-SOL-1 (R3.2) — roster `member_display_state_digest`. SHA-256 over RFC
/// 8785 JCS canonical JSON of `{realm_id, actor_id, effective_events:
/// [{event_id, segment, payload_digest}], handle_claims:[{claim_digest,
/// binding_state, expires_at}]}` (handle_claims sorted by claim_digest).
/// Byte-compatible with the SDK `member_display_state_digest` helper. The
/// caller passes the disclosure-visible handle-claim digest set; contexts
/// without visible handle evidence pass an empty slice.
pub(crate) fn display_state_digest(
    realm_id: &str,
    actor_id: &str,
    entries: &[EffectiveIdentityEntry],
    handle_claims: &[HandleClaimDigestInput],
) -> Option<String> {
    let mut handle_claims: Vec<Value> = handle_claims
        .iter()
        .map(|claim| {
            let mut value = serde_json::Map::new();
            value.insert(
                "claim_digest".to_owned(),
                serde_json::json!(claim.claim_digest),
            );
            value.insert(
                "binding_state".to_owned(),
                serde_json::json!(claim.binding_state),
            );
            if let Some(expires_at) = &claim.expires_at {
                value.insert("expires_at".to_owned(), serde_json::json!(expires_at));
            }
            Value::Object(value)
        })
        .collect();
    handle_claims.sort_by(|a, b| {
        a.get("claim_digest")
            .and_then(Value::as_str)
            .cmp(&b.get("claim_digest").and_then(Value::as_str))
    });
    let projection = serde_json::json!({
        "realm_id": realm_id,
        "actor_id": actor_id,
        "effective_events": effective_events_projection(entries),
        "handle_claims": handle_claims,
    });
    canonical_digest(
        &projection,
        realm_id,
        actor_id,
        "member_display_state_digest",
    )
}

fn canonical_digest(
    projection: &Value,
    realm_id: &str,
    actor_id: &str,
    label: &str,
) -> Option<String> {
    match cokret_sdk::canonical::canonical_json_bytes(projection) {
        Ok(bytes) => Some(cokret_sdk::canonical::sha256_digest(bytes)),
        Err(err) => {
            tracing::warn!(%err, %realm_id, %actor_id, %label, "member identity digest canonicalization failed");
            None
        }
    }
}

/// Single-process service state. Every long-lived data surface lives behind
/// `persistence` (a `dyn PersistenceStore`); the few remaining fields are
/// either non-record state (config, db pool, hlc, authz engine) or runtime
/// facets that don't fit the trait shape (in-memory `RealmDirectoryIndex`,
/// `CompositeDidResolver`, `ProjectionState`).
#[derive(Clone)]
pub struct AppState {
    pub config: AppConfig,
    pub db: Db,
    pub persistence: Arc<dyn PersistenceStore>,
    pub object_storage: Arc<dyn ObjectStorage>,
    pub hlc: ServerHlc,
    pub projection: Arc<Mutex<ProjectionState>>,
    pub authz: AuthzEngine,
    pub realms: Arc<Mutex<RealmDirectoryIndex>>,
    /// Cross-signing state machine (PSK→SSK/USK publishes + device trust
    /// chains), per spec crypto-media/device-lifecycle.md §5. Fed by the
    /// projector when `ck.cross_signing.publish` lands, and read when verifying
    /// a `ck.device.authorize` `cross_signing_binding`. In-memory like the other
    /// reducer projections; durable rehydration rides on the durable event
    /// store (control-realm Phase 3).
    pub cross_signing: Arc<Mutex<cokret_sdk::DeviceManager>>,
    /// In-memory handle release ledger. Records `released_handle → released_at`
    /// for every handle vacated by `claim_handle` / `transfer_handle`; new
    /// claims for a handle still inside `HANDLE_GRACE_PERIOD_SECONDS` are
    /// rejected with `handle_in_grace_period`. Spec: identity-handles.md
    /// (handle release cooldown). The map is server-process-local; persistent
    /// storage lands when the handle CRDT projection ships.
    pub handle_releases: Arc<Mutex<BTreeMap<String, chrono::DateTime<chrono::Utc>>>>,
    /// Account lifecycle state projection keyed by actor DID. Missing rows
    /// mean `active`; non-active rows gate auth/session issuance and directory
    /// visibility. Kept beside `erased_actors` until the durable account-state
    /// projection lands.
    pub account_lifecycle: Arc<Mutex<BTreeMap<String, AccountLifecycleRecord>>>,
    /// Erased actors — DID set. Once an actor `erase`s itself, every
    /// subsequent authenticated request from that bearer returns 401
    /// `account_erased` (and directory hits skip the row). Same in-memory
    /// trade-off as `handle_releases`: persistent ledger lands with the
    /// account-state projection.
    pub erased_actors: Arc<Mutex<BTreeSet<String>>>,
    /// In-memory failed-auth counter, keyed by actor DID.
    /// Spec: A.3 — auth handlers (`dev-login`,
    /// `session-grant/exchange`) bump the counter on failure; once it
    /// crosses `ACCOUNT_LOCKOUT_THRESHOLD` (5) within the active window
    /// the actor is locked out for `ACCOUNT_LOCKOUT_DURATION` (15 min).
    /// A successful login clears the row. Durable storage lands with
    /// the account-state projection.
    pub failed_login_attempts: Arc<Mutex<BTreeMap<String, FailedLoginRecord>>>,
    /// Per-actor notifications read marker. `mark_all_read(actor)` writes
    /// `Utc::now()`; the notifications read-side filter uses it to flag
    /// rows as read. Same in-memory shape as the other two.
    pub notification_read_cursors: Arc<Mutex<BTreeMap<String, chrono::DateTime<chrono::Utc>>>>,
    /// Stateful account-sync cursor handle table. The wire cursor only carries
    /// `{v,purpose,t,x,h}`; this map binds `h` to authenticated context and
    /// stream positions. Durable storage can replace it without changing the
    /// account subscribe API.
    pub sync_cursor_handles: Arc<Mutex<BTreeMap<String, Value>>>,
    /// Monotonic position allocator for to-device queues. Cursor ack uses
    /// numeric `position <= ack_position` pruning, so positions must advance
    /// even when multiple fanout writes land in the same wall-clock microsecond.
    pub to_device_position_counter: Arc<AtomicI64>,
    /// Holder-private consent cell projection keyed by
    /// `(holder_did, peer_did, scope)`. This is the minimal G3.S4
    /// reducer cache that backs `/_cokret/self/consent/cells/*` and the contact
    /// gate; durable Move/Anchor cell hydration can replace the backing map
    /// without changing the routing contract.
    pub consent_cells: Arc<Mutex<BTreeMap<ConsentCellKey, ConsentCellRecord>>>,
    /// Runtime state for sovereign-main / enclave deployment handshakes,
    /// trust-root decisions, boundary audit, and store-and-forward queues.
    /// The P2-056 implementation keeps this in memory so the dual-soland
    /// conformance harness can exercise the protocol shape locally; a durable
    /// store can replace the backing map without changing the HTTP contract.
    pub sovereign_deployment: Arc<Mutex<SovereignDeploymentState>>,
    /// Per-Realm retention policy projection. The policy is derived from
    /// `retention_policy` fields on accepted Realm events and can be driven
    /// by the local admin/test sweeper. A durable store can replace this
    /// in-memory map without changing the read-side tombstone contract.
    pub retention_policies: Arc<Mutex<BTreeMap<String, RetentionPolicyRecord>>>,
    /// Retention tombstones keyed by event_id. Tombstoned events keep their
    /// stable event_id and remain in the canonical/projection stores; render
    /// paths redact the content to `[expired]`.
    pub retention_tombstones: Arc<Mutex<BTreeMap<String, RetentionTombstoneRecord>>>,
    /// Best-effort federation block hints keyed by `(actor, blocked, source)`.
    /// These hints are not Realm facts; they let a peer suppress unnecessary
    /// push fanout for `blocked -> actor` without leaking anything into public
    /// membership or moderation state.
    pub federation_block_hints: Arc<Mutex<BTreeMap<String, FederationBlockHintRecord>>>,
    /// Local organization directory rows keyed by organization DID/id. This is
    /// the P2 governance projection surface used by organization moderation
    /// policy and directory reads until a durable organization table lands.
    pub organizations: Arc<Mutex<BTreeMap<String, OrganizationRecord>>>,
    /// Current organization moderation policy per organization.
    pub organization_policies: Arc<Mutex<BTreeMap<String, OrganizationPolicyRecord>>>,
    /// Space -> organizations declared by `cx.realm.create.owning_organizations`
    /// or the local organization link endpoint.
    pub space_organizations: Arc<Mutex<BTreeMap<String, BTreeSet<String>>>>,
    /// Organization -> member Realm ids. This is the read-side fanout index:
    /// policy updates do not rewrite per-space rows.
    pub organization_spaces: Arc<Mutex<BTreeMap<String, BTreeSet<String>>>>,
    /// Accepted Space-level moderation-policy overrides keyed by Realm id.
    pub space_moderation_policies: Arc<Mutex<BTreeMap<String, SpaceModerationPolicyRecord>>>,
    pub did_resolver: Arc<Mutex<CompositeDidResolver>>,
    /// Move/Anchor/Lattice runtime stores.
    /// In-memory backends from the SDK; production deployments will
    /// swap these for Pg-backed implementations behind the same trait
    /// surface (`MoveStore` / `AnchorStore` / `CellStore` / `CellRegistry`).
    pub move_store: Arc<cokret_sdk::state_res::MemoryMoveStore>,
    pub anchor_store: Arc<cokret_sdk::state_res::MemoryAnchorStore>,
    pub cell_store: Arc<cokret_sdk::state_res::MemoryCellStore>,
    pub cell_registry: Arc<cokret_sdk::state_res::MemoryCellRegistry>,
    /// Live event notification channel for `ck.events.subscribe`
    /// long-poll/SSE streaming. Writers
    /// (`routing::events::projection::project_accepted_operations`,
    /// `routing::federation::move_anchor::submit_anchor`,
    /// `crate::anchorer::AnchorerWorker`) broadcast each accepted
    /// projection event; subscribers in `routing::events::sync::events_subscribe`
    /// `recv()` on a fresh receiver and write live frames to the NDJSON
    /// streaming response. Capacity 1024 — enough for a multi-Space
    /// principal under burst load; receivers that fall behind get
    /// `RecvError::Lagged` and emit a `dropped` control frame to nudge
    /// the client to resync.
    pub event_broadcast: broadcast::Sender<EventNotification>,
    /// Server-enforced reconnect windows advertised by subscribe control
    /// frames. This prevents a faulty or overloaded client from immediately
    /// re-opening the same subscribe scope after `dropped` /
    /// `resync_required`.
    pub subscribe_reconnect_gate: Arc<Mutex<SubscribeReconnectGate>>,
    /// Persistent Ed25519 signing key for AnchorerWorker +
    /// admin endpoints (`admin_reconfigure_anchorer`, `admin_repair_bottom`).
    /// Loaded from `AppConfig::anchorer_signing_key_seed` at boot when set;
    /// otherwise minted from `sha256(service_did || nanos_since_epoch)` and
    /// flagged as `AnchorerSigningKeyOrigin::Ephemeral` so a sticky-warn
    /// fires on first use.
    ///
    /// Shared across all signing paths so the AnchorerWorker, the
    /// `service_admin_signer` admin shortcut, and the threshold partial-
    /// signature coordinator all bind to the **same** key/DID identity.
    /// Swapped lock-free via [`ArcSwap`] so
    /// the `POST /_soland/admin/spaces/{id}/anchorer/rotate-signing-key`
    /// endpoint can publish a fresh ed25519 seed without tearing concurrent
    /// signing passes. Readers acquire the current key via `load_full()`
    /// (returns `Arc<SigningKey>`); writers `store(...)` a new `Arc`.
    pub anchorer_signing_key: Arc<ArcSwap<SigningKey>>,
    /// The origin tag rotates with the key. Stored alongside it
    /// behind a [`Mutex`] (one-shot writes from the rotation path are not
    /// in the hot read path; the per-pass diagnostic helper just snapshots).
    pub anchorer_signing_key_origin: Arc<Mutex<AnchorerSigningKeyOrigin>>,
    /// Per-admin signing keys: SDK
    /// [`cokret_sdk::AdminKeyStore`] keyed by the `application_id`
    /// `soland.<service_did>`. Each admin DID in
    /// `config.admin_principal_dids` gets its own ed25519 signing seed
    /// (provisioned at boot in `development_mode`; lazily loaded from the
    /// platform keystore otherwise). The signer for an admin DID is
    /// built via `admin_signer_for(state, admin_did)` — this replaces the
    /// service-wide `service_admin_signer` shortcut for endpoints that
    /// want operator attribution in the audit chain.
    pub admin_keystore: Arc<cokret_sdk::AdminKeyStore>,
    /// G4.T3 — verified-profile descriptors loaded from the artifact path in
    /// `SOLAND_VERIFIED_PROFILES_ARTIFACT` at startup. Filtered to entries
    /// whose `service_role == "principal_server"` and additionally
    /// cross-checked against the local `claimed_profiles[]` set inside
    /// `describe.rs::apply_claim_level_partition`. Empty when the env var
    /// is unset / file missing / file malformed — that's the dev-mode
    /// invariant in service-surface.md §3.0.
    pub verified_profiles: Arc<Vec<VerifiedProfileDescriptor>>,
    /// MID-1..6 (R3.1 spec-sync 2026-05-27, cokret-spec @ 7157ee8) — in-
    /// memory registry of `ck.member.identity.update` events. Reducer
    /// dispatch (`apply_member_identity_update`) and the sync roster
    /// projection (`SYNC-MEM-1..3`) both go through this. See
    /// [`MemberIdentityRegistry`] above for storage and effective-set
    /// semantics; durable persistence lands when the MID schema migration
    /// ships. Plaintext Ed25519 MemberIdentity proofs are verified on
    /// event ingest; encrypted/non-Ed25519 proof forms are refused
    /// fail-closed. Reducer-shape validation (digest binding, segment
    /// whitelist) IS real per MID-2.
    pub member_identity: Arc<Mutex<MemberIdentityRegistry>>,
}

#[derive(Clone, Debug)]
pub struct SessionRecord {
    pub token_hash: String,
    pub actor: String,
    pub device_id: String,
    pub audience: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Debug)]
pub struct DeviceInventoryRecord {
    pub actor: String,
    pub device_id: String,
    pub display_name: Option<String>,
    pub verification_state: String,
    pub payload: Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Debug)]
pub struct AccountRecord {
    pub did: String,
    pub handle: String,
    pub display_name: Option<String>,
    /// Free-form short description for directory rendering. Updated via
    /// `POST /_cokret/self/account/profile` (operationId `cx.account.update_profile`);
    /// rendered by `demo_actors` in directory search results.
    pub bio: Option<String>,
    /// HTTPS URL pointing at the actor's avatar image. Server holds the
    /// link verbatim — no transcoding or caching.
    pub avatar_url: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct AccountLifecycleRecord {
    pub state: String,
    pub reason: Option<String>,
    pub changed_by: Option<String>,
    pub changed_at: chrono::DateTime<chrono::Utc>,
}

/// REC-1 (R3 spec-sync 2026-05-27, cokret-spec b47ff6ec) — accepted
/// recovery policy snapshot persisted by `RecoveryPolicyStore`.
///
/// Spec: `cokret-spec/spec/v1/artifacts/schemas/recovery-policy.schema.json`.
#[derive(Clone, Debug)]
pub struct RecoveryPolicyRecord {
    pub policy_id: String,
    pub principal_id: String,
    pub version: u32,
    pub trust_domain: String,
    pub allowed_proof_kinds: Vec<String>,
    pub supersedes: Option<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub issued_at: chrono::DateTime<chrono::Utc>,
    pub raw_payload: Value,
    pub accepted_at: chrono::DateTime<chrono::Utc>,
    /// Verification-method DID URL of the issuer. The full proof
    /// verification (signature + signed_fields enforcement) is flagged
    /// `TODO(R4): wire principal signing-key resolver + signature
    /// validation through DidResolver chain`.
    pub verification_method: String,
}

/// REC-1 — accepted recovery receipt snapshot.
///
/// Spec: `cokret-spec/spec/v1/artifacts/schemas/recovery-receipt.schema.json`.
#[derive(Clone, Debug)]
pub struct RecoveryReceiptRecord {
    pub receipt_id: String,
    pub principal_id: String,
    pub recovery_session_id: String,
    pub policy_id: String,
    pub policy_version: u32,
    pub trust_domain: String,
    pub new_device_id: String,
    pub proof_digest: String,
    pub outcome: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: chrono::DateTime<chrono::Utc>,
    pub raw_payload: Value,
    pub verification_method: String,
    pub accepted_at: chrono::DateTime<chrono::Utc>,
}

/// C-P2 (REC-1) — recovery session lifecycle record.
///
/// A session binds a requesting device to the principal's active recovery
/// policy snapshot + a server challenge, and transitions
/// `pending -> verified -> completed` (or `rejected` / `expired`). Proof
/// verification (C-P3) is what advances `pending -> verified`; completion
/// (C-P4) emits a `ck.device.authorize` + receipt.
#[derive(Clone, Debug)]
pub struct RecoverySessionRecord {
    pub recovery_session_id: String,
    pub principal_id: String,
    pub requesting_device_id: String,
    pub trust_domain: String,
    pub policy_id: String,
    pub policy_version: u32,
    /// Accepted cross-signing generation snapshotted at session creation. The
    /// recovery proof transcript binds it, and completion (C-P4) MUST reject if
    /// the current accepted generation no longer equals this value
    /// (`device_recovery_ssk_generation_mismatch`). Spec: device-lifecycle.md §15.
    pub ssk_generation: u32,
    /// Snapshot of the active policy at session-creation time (so a later policy
    /// rotation cannot retroactively change what this session was bound to).
    pub policy_payload: Value,
    /// Server-issued anti-replay challenge the proof transcript MUST bind.
    pub challenge: String,
    /// `pending` | `verified` | `completed` | `rejected` | `expired`.
    pub state: String,
    /// The submitted proof payload (recorded on `/proofs`; verified in C-P3).
    pub proof_payload: Option<Value>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Per-actor failed-login bookkeeping. Spec: A.3 — five failures within
/// the active window flip the actor into a 15-minute lockout. The record
/// is cleared on any successful login.
#[derive(Clone, Debug)]
pub struct FailedLoginRecord {
    /// Number of failed attempts observed in the current window.
    pub attempts: u32,
    /// When the most recent failure was recorded. Drives the rolling
    /// window check: failures older than `ACCOUNT_LOCKOUT_WINDOW` reset
    /// the counter rather than locking the actor.
    pub last_failure_at: chrono::DateTime<chrono::Utc>,
    /// `Some(until)` if the actor is currently locked out — auth
    /// handlers return `account_locked` until `Utc::now() >= until`.
    pub locked_until: Option<chrono::DateTime<chrono::Utc>>,
}

/// Threshold of consecutive failed auth attempts before the actor is
/// locked out. Spec: A.3.
pub const ACCOUNT_LOCKOUT_THRESHOLD: u32 = 5;
/// Lockout window — once the actor crosses [`ACCOUNT_LOCKOUT_THRESHOLD`]
/// they stay locked for this long. Spec: A.3.
pub const ACCOUNT_LOCKOUT_DURATION: chrono::Duration = chrono::Duration::minutes(15);
/// Rolling window over which failed attempts accumulate. Failures older
/// than this reset the counter rather than escalating to a lockout.
pub const ACCOUNT_LOCKOUT_WINDOW: chrono::Duration = chrono::Duration::minutes(15);

#[derive(Clone, Debug)]
pub struct WebvhDocumentRecord {
    pub did: String,
    pub did_document: Value,
    pub key_log_head: Option<String>,
    pub seq: u64,
    pub method_evidence: Value,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct WebvhLogRecord {
    pub event_digest: String,
    pub did: String,
    pub seq: u64,
    pub operation: Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct ContactRecord {
    pub requester: String,
    pub target: String,
    pub scope: String,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConsentCellKey {
    pub holder: String,
    pub peer: String,
    pub scope: String,
}

#[derive(Clone, Debug)]
pub struct ConsentGrantDot {
    pub dot: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub granted_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct ConsentCellRecord {
    pub holder: String,
    pub peer: String,
    pub scope: String,
    pub cell_id: String,
    pub requested_at: Option<chrono::DateTime<chrono::Utc>>,
    pub grant_dots: BTreeMap<String, ConsentGrantDot>,
    pub revoked_dots: BTreeSet<String>,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Actor-private account data row (`ck.account_data.set` storage).
///
/// One row per `(actor, data_type)`. `data_type` is the canonical wire key
/// (e.g. `ck.read_receipt.preferences`, `cx.contacts.actor.did:web:alice.example`,
/// `cx.contacts.space.ck:space:0196419b-0000-7000-8000-000000000000`). Soland
/// treats the `payload` as an opaque encrypted blob — no schema validation
/// happens server-side; clients are responsible for canonical encoding.
///
/// Spec: `discovery/client-preferences.md` §2 (storage model) and §3.7
/// (Space remarks, `cx.contacts.space.<realm_id>`).
#[derive(Clone, Debug)]
pub struct AccountDataRecord {
    pub actor: String,
    pub data_type: String,
    pub payload: Value,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct SpaceInviteRecord {
    pub invite_id: String,
    pub realm_id: String,
    pub inviter: String,
    pub invitee: Option<String>,
    pub invite_token: String,
    pub status: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct RealmMetaRecord {
    pub owner: String,
    pub deleted: bool,
    pub discoverability: String,
    /// One of `world_readable` / `shared` / `invited` / `joined` /
    /// `restricted`. `restricted` is fail-closed unless
    /// `history_sharing_policy` has an explicit matching rule.
    pub history_visibility: String,
    /// Effective `cx.realm.history_sharing_policy.value` plus its canonical
    /// digest. The policy gates E2EE history key shares and restricted history
    /// reads; history visibility alone never grants old epoch keys.
    pub history_sharing_policy: Option<Value>,
    pub history_sharing_policy_digest: Option<String>,
    /// Effective `cx.realm.preview_policy.value` plus its canonical digest.
    /// Directory/object preview must fail closed when this is missing.
    pub preview_policy: Option<Value>,
    pub preview_policy_digest: Option<String>,
    /// Optional encryption profile (`mls_rfc9420` / `plaintext`). Cross-checked
    /// against `history_visibility` at create time — `mls_rfc9420` is
    /// incompatible with `world_readable` (space-and-place.md §3.1.3).
    pub encryption_profile: Option<String>,
    pub plaintext_visible_services: BTreeSet<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct MessageRecord {
    pub event_id: String,
    pub realm_id: String,
    pub sender: String,
    pub thread_id: String,
    pub content: Value,
    pub encrypted: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct CanonicalEventRecord {
    pub event_id: String,
    pub actor_id: String,
    pub actor_seq: u64,
    pub realm_id: Option<String>,
    pub kind: String,
    pub schema_id: String,
    pub canonical_digest: String,
    pub canonical_bytes: Vec<u8>,
    pub envelope: Value,
    pub received_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct ProjectionEventRecord {
    pub event_id: String,
    pub realm_id: String,
    /// Canonical Cokret event kind (e.g. `ck.message.create`).
    pub event_kind: String,
    pub operation_type: String,
    pub operation_id: Option<String>,
    pub sender: Option<String>,
    pub payload: Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct DeviceMessageRecord {
    pub idempotency_key: String,
    pub sender: String,
    pub recipient: String,
    pub device_id: String,
    pub position: i64,
    pub content: Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct BlobRecord {
    pub sha256: String,
    pub size_bytes: i64,
    pub storage_backend: String,
    pub storage_key: String,
    pub media_type: String,
    pub filename: Option<String>,
    pub realm_id: Option<String>,
    pub encryption: Option<Value>,
    pub uploaded_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct FederationTransactionRecord {
    pub origin: String,
    pub txn_id: String,
    pub destination: String,
    pub realm_id: Option<String>,
    pub content_digest: String,
    pub status: String,
    pub response: Value,
    pub received_at: chrono::DateTime<chrono::Utc>,
    pub processed_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// G3.S0 — one outbound federation HTTP POST queued for the
/// `FederationDispatcher` background worker. See
/// `routing/federation/outbox.rs` for the worker loop and
/// `migrations/20260520000000_federation_outbox/up.sql` for the durable
/// schema.
///
/// Timestamps are stored as unix-seconds (`i64`) to match the SQLite-style
/// schema defined in the spec subset; the Pg-backed store maps them to
/// `BIGINT`. The reason we don't use `TIMESTAMPTZ` here is so the SDK +
/// in-memory backend share the exact same numeric encoding the wire
/// receipts (`Idempotency-Key`, dispatcher logs) compare against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FederationOutboxRecord {
    /// ULID/UUID — primary key.
    pub id: String,
    /// Peer DID (mirrors `federation_peers[i]`; today we treat the
    /// configured peer URL as both did + url because the discovery layer
    /// resolving DID → service endpoints lands in a later milestone).
    pub peer_did: String,
    /// Fully-qualified peer base URL (no trailing slash) the dispatcher
    /// concatenates with `endpoint` to form the POST target.
    pub peer_url: String,
    /// Endpoint path on the peer, e.g.
    /// `/_cokret/peer/federation/push-operations` or
    /// `/_cokret/peer/federation/anchors`.
    pub endpoint: String,
    /// `Idempotency-Key` header value the dispatcher sends. Derived
    /// deterministically from `(origin, resource_kind, resource_id)` so
    /// retries collapse onto the same row server-side per
    /// `federation.md` §8.5.
    pub idempotency_key: String,
    /// Canonical request body the dispatcher POSTs verbatim.
    pub payload_json: String,
    /// Number of completed delivery attempts (excluding the next one).
    pub attempts: i32,
    /// Unix seconds — earliest time the worker may pick this row.
    pub next_attempt_at: i64,
    /// Last observed HTTP status code, or `-1` after the worker gave up
    /// (attempts cap reached on retryable error). `None` until the first
    /// attempt completes.
    pub last_status: Option<i32>,
    /// First ~1 KiB of the most recent response body, for postmortem.
    pub last_response_excerpt: Option<String>,
    /// Unix seconds — when the row was enqueued.
    pub created_at: i64,
    /// Unix seconds — when delivery terminated (2xx success, permanent
    /// 4xx failure, or the gave-up sentinel). `None` while the row is
    /// still pending.
    pub delivered_at: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FederationOutboxDeadLetterRecord {
    pub id: String,
    pub outbox_id: String,
    pub peer_did: String,
    pub endpoint: String,
    pub idempotency_key: String,
    pub terminal_status: i32,
    pub attempts: i32,
    pub response_excerpt: Option<String>,
    pub failed_at: i64,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub struct PresenceRecord {
    pub actor: String,
    pub status: String,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct TypingRecord {
    pub actor: String,
    pub realm_id: String,
    pub scope_id: Option<String>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct PushRuleRecord {
    pub actor: String,
    pub rule_id: String,
    pub enabled: bool,
    pub actions: Vec<String>,
    pub conditions: Value,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct OutboundPushBridgeCacheRecord {
    pub push_gateway_url: String,
    pub service_base_url: String,
    pub bridge_describe_url: String,
    pub fetch_state: String,
    pub cache_state: String,
    pub contract_digest: String,
    pub fetched_at: chrono::DateTime<chrono::Utc>,
    pub remote_contract: Value,
    /// Explicit trust state for the cached snapshot. This introduces
    /// `pending` / `trusted` / `revoked` so `verify_contract_freshness` can
    /// fail-closed when a snapshot has not yet been promoted to trusted.
    pub trust_level: String,
    /// Last time we affirmatively re-checked the upstream contract; bumped
    /// independently from `fetched_at` so freshness/age policy can reject
    /// snapshots that haven't been re-verified within `max_age`.
    pub freshness_at: chrono::DateTime<chrono::Utc>,
    /// Opaque server-issued ETag from the upstream describe response.
    /// Compared alongside `contract_digest` so a same-digest-but-rotated
    /// etag still trips drift fail-closed.
    pub etag: String,
}

#[derive(Clone, Debug)]
pub struct WebrtcSessionRecord {
    pub session_id: String,
    pub realm_id: String,
    pub created_by: String,
    pub participants: BTreeSet<String>,
    pub mode: String,
    pub recording_policy: String,
    pub recording_started_by: Option<String>,
    pub recording_blob_ref: Option<String>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub next_seq: u64,
    pub signals: Vec<WebrtcSignalRecord>,
}

#[derive(Clone, Debug)]
pub struct WebrtcSignalRecord {
    pub seq: u64,
    pub sender: String,
    pub message_type: String,
    pub payload: Value,
    pub proofs: Vec<Value>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// One row of the persistent multisig coordinator buffer.
///
/// Holds an in-flight pending Anchor that is awaiting threshold partial
/// signatures. The `partials` map is keyed by signer DID → submitted partial
/// payload (`{signature_b64, kid, submitted_at}`). When the number of
/// partials reaches `threshold_k`, the leader aggregates them via SDK
/// `ThresholdAggregator` and publishes the final threshold-signed Anchor,
/// then deletes the row.
#[derive(Clone, Debug)]
pub struct MultisigPendingRecord {
    pub anchor_id: String,
    pub realm_id: String,
    pub threshold_k: u32,
    pub threshold_n: u32,
    pub members: Vec<String>,
    /// Canonical bytes (base64) the partial signatures sign over. Empty when
    /// the buffer was created without an explicit canonical body (smoke
    /// tests). Real partial-signature aggregation requires this to be
    /// non-empty.
    pub canonical_b64: String,
    /// `signer_did` -> JSON `{signature_b64, kid, submitted_at}`.
    pub partials: BTreeMap<String, Value>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Node id of the watchdog instance currently leasing this row, or
    /// `None` when unclaimed. The lease is valid until
    /// [`MultisigPendingRecord::claimed_until`].
    pub claimed_by_node_id: Option<String>,
    /// Lease expiry timestamp. A row is "claimable" when this is `None` or
    /// in the past.
    pub claimed_until: Option<chrono::DateTime<chrono::Utc>>,
    /// Partition-tolerant fencing token. Every successful
    /// `try_claim` bumps this counter; a stale leader (whose lease was
    /// silently superseded after a network partition healed) carries the
    /// pre-bump value so its post-aggregate `delete_with_fence` /
    /// `renew_claim` is rejected at the row level. Monotonic across the
    /// row's lifetime.
    pub claim_seq: i64,
}

#[derive(Clone, Debug)]
pub struct PolicyDocumentRecord {
    pub policy_id: String,
    pub owner: String,
    pub scope: String,
    pub subject_ref: String,
    pub policy_type: String,
    pub payload: Value,
    pub active: bool,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct OrganizationRecord {
    pub organization_id: String,
    pub organization_did: String,
    pub handle: Option<String>,
    pub display_name: String,
    pub verified: bool,
    pub members: BTreeSet<String>,
    pub member_count: usize,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct OrganizationPolicyRecord {
    pub organization_id: String,
    pub policy_id: String,
    pub payload: Value,
    pub version: u64,
    pub updated_by: String,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct SpaceModerationPolicyRecord {
    pub realm_id: String,
    pub payload: Value,
    pub updated_by: String,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, Default)]
pub struct SovereignDeploymentState {
    pub profile_override: Option<String>,
    pub upstream_main: Option<String>,
    pub trust_roots: Vec<String>,
    pub allow_external_via_enclave: bool,
    pub trusted_enclaves: BTreeMap<String, SovereignEnclaveRecord>,
    pub enclave_realms: BTreeMap<String, SovereignRealmRecord>,
    pub external_invites: BTreeMap<String, SovereignExternalInviteRecord>,
    pub external_accounts: BTreeMap<String, SovereignExternalAccountRecord>,
    pub audit_log: Vec<SovereignAuditRecord>,
    pub upstream_available: bool,
    pub store_forward_queue: Vec<SovereignStoreForwardRecord>,
    pub received_store_forward: Vec<SovereignStoreForwardRecord>,
}

#[derive(Clone, Debug)]
pub struct SovereignEnclaveRecord {
    pub server_id: String,
    pub base_url: String,
    pub trust_chain: Vec<String>,
    pub registered_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct SovereignRealmRecord {
    pub realm_id: String,
    pub deployment_profile: String,
    pub hosted_on: String,
    pub external_invite_policy: String,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub enclave_frontier: i64,
    pub main_frontier: i64,
}

#[derive(Clone, Debug)]
pub struct SovereignExternalInviteRecord {
    pub invite_token: String,
    pub target_realm: String,
    pub target_host: String,
    pub invitee: String,
    pub inviter: String,
    pub accepted: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct SovereignExternalAccountRecord {
    pub did: String,
    pub realm_id: String,
    pub bound_node: String,
    pub trust_chain_profile: String,
    pub active: bool,
    pub joined_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct SovereignAuditRecord {
    pub subject: String,
    pub action: String,
    pub realm_id: Option<String>,
    pub status: String,
    pub detail: Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct SovereignStoreForwardRecord {
    pub id: String,
    pub realm_id: String,
    pub actor: String,
    pub content: Value,
    pub state: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub forwarded_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Debug)]
pub struct RetentionPolicyRecord {
    pub realm_id: String,
    pub ttl_seconds: i64,
    pub updated_by: String,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct RetentionTombstoneRecord {
    pub event_id: String,
    pub realm_id: String,
    pub reason: String,
    pub policy_ttl_seconds: i64,
    pub expired_at: chrono::DateTime<chrono::Utc>,
    pub tombstoned_at: chrono::DateTime<chrono::Utc>,
    pub anchored: bool,
}

#[derive(Clone, Debug)]
pub struct FederationBlockHintRecord {
    pub actor: String,
    pub blocked: String,
    pub source: String,
    pub received_at: chrono::DateTime<chrono::Utc>,
}

impl AppState {
    /// Snapshot the persistent Ed25519 signing key shared by
    /// the AnchorerWorker and all admin signing paths. Returns a fresh
    /// `Arc<SigningKey>` (lock-free `ArcSwap::load_full`) so callers can
    /// hold the snapshot for the duration of a signing pass even if the
    /// rotate-signing-key endpoint races with them.
    pub fn anchorer_signing_key(&self) -> Arc<SigningKey> {
        self.anchorer_signing_key.load_full()
    }

    /// Origin tag for diagnostics (`Configured` / `Ephemeral` / `Rotated`).
    pub fn anchorer_signing_key_origin(&self) -> AnchorerSigningKeyOrigin {
        *self
            .anchorer_signing_key_origin
            .lock()
            .expect("anchorer signing key origin lock")
    }

    /// Hot-rotate the AnchorerWorker signing key. Writers swap
    /// the `ArcSwap` and update the origin tag in lockstep. Returns the
    /// newly-published `Arc<SigningKey>` for callers (the rotate-signing-key
    /// endpoint uses it to compute the resulting did:key kid).
    pub fn rotate_anchorer_signing_key(
        &self,
        seed: &[u8; 32],
        origin: AnchorerSigningKeyOrigin,
    ) -> Arc<SigningKey> {
        let new_key = Arc::new(SigningKey::from_bytes(seed));
        self.anchorer_signing_key.store(new_key.clone());
        if let Ok(mut guard) = self.anchorer_signing_key_origin.lock() {
            *guard = origin;
        }
        new_key
    }

    pub fn new(config: AppConfig, db: Db) -> Self {
        let persistence: Arc<dyn PersistenceStore> = db
            .pool
            .as_ref()
            .map(|pool| {
                Arc::new(PgPersistenceStore::new(pool.clone())) as Arc<dyn PersistenceStore>
            })
            .unwrap_or_else(|| Arc::new(MemoryPersistenceStore::new()));
        Self::new_with_persistence(config, db, persistence)
    }

    pub fn new_with_persistence(
        config: AppConfig,
        db: Db,
        persistence: Arc<dyn PersistenceStore>,
    ) -> Self {
        let mut realms = RealmDirectoryIndex::new();
        let now = chrono::Utc::now();

        let service_did = config.service_did.clone();

        let object_storage = build_object_storage(&config.object_storage)
            .expect("object storage backend initializes");

        // Seed the deterministic demo Realm into the in-memory directory index
        // when explicitly opted in (tests via `test_config()`, dev harnesses via
        // `SOLAND_SEED_DEMO_DATA=true`). In production this stays off so soland
        // deployments don't all advertise the same hard-coded "Cokret Demo
        // Space" id across federation peers.
        //
        // The DB-touching half of the demo seed (writing the demo account +
        // Realm metadata through the now-async persistence store) and the
        // durable hydration steps run in [`AppState::hydrate`], an explicit
        // async boot step driven from `main`, so the synchronous constructor
        // never touches the database.
        if config.seed_demo_data {
            let demo_realm_id = "ck:realm:0196419b-0000-7000-8000-000000000000";
            let mut demo = RealmDirectoryEntry::new(
                RealmId::new(demo_realm_id.to_owned()).expect("valid demo Realm id"),
                "Cokret Demo Realm",
            );
            demo.description = Some("Shared demo Realm served by soland".to_owned());
            demo.public = true;
            demo.members
                .insert(Did::new("did:web:alice.example").expect("valid did"));
            demo.tags.insert("demo".to_owned());
            demo.category = Some("collaboration".to_owned());
            realms.upsert(demo);
        }

        // Build the production DID resolver chain before the struct literal
        // so we can still
        // borrow `&config` for the helper before `config` itself is
        // moved into `Self.config`.
        let did_resolver = Arc::new(Mutex::new(
            self::did_resolver_chain::build_did_resolver_chain_with_identity(
                &config,
                Some(persistence.clone()),
            ),
        ));

        // Derive the AnchorerWorker's Ed25519 signing key.
        // Resolution order:
        //   1. KeyStore (when `use_keystore=true` and the platform store has a previously-persisted
        //      seed under our id) → Configured.
        //   2. `config.anchorer_signing_key_seed` (env-loaded) → Configured. When
        //      `use_keystore=true` we *also* persist this seed back to the KeyStore on first boot
        //      so subsequent restarts skip the env path.
        //   3. SHA-256(service_did || boot_nanos) → Ephemeral.
        let (signing_seed, anchorer_signing_key_origin) =
            (|| -> ([u8; 32], AnchorerSigningKeyOrigin) {
                if config.use_keystore {
                    let app_id = format!("soland.{service_did}");
                    let key_id = format!("cokret:signer:soland-anchorer:{service_did}");
                    let store = cokret_sdk::platform_default_keystore(&app_id);
                    if let Ok(bytes) = store.load(&key_id) {
                        if bytes.len() == 32 {
                            let mut seed = [0u8; 32];
                            seed.copy_from_slice(&bytes);
                            tracing::info!(%key_id, "loaded anchorer signing seed from platform KeyStore");
                            return (seed, AnchorerSigningKeyOrigin::Configured);
                        }
                        tracing::warn!(%key_id, len = bytes.len(),
                        "platform KeyStore returned non-32-byte payload; falling back");
                    }
                    if let Some(seed) = config.anchorer_signing_key_seed {
                        if let Err(error) = store.store(&key_id, &seed) {
                            tracing::warn!(%error, %key_id,
                            "failed to seed platform KeyStore from env-supplied seed");
                        } else {
                            tracing::info!(%key_id,
                            "persisted env-supplied anchorer seed into platform KeyStore");
                        }
                        return (seed, AnchorerSigningKeyOrigin::Configured);
                    }
                    // Mint + persist a one-shot seed.
                    let mut seed = [0u8; 32];
                    getrandom_seed(&mut seed);
                    if let Err(error) = store.store(&key_id, &seed) {
                        tracing::warn!(%error, %key_id,
                        "failed to persist freshly-minted anchorer seed to KeyStore");
                    } else {
                        tracing::info!(%key_id,
                        "minted + persisted fresh anchorer seed via platform KeyStore");
                    }
                    return (seed, AnchorerSigningKeyOrigin::Configured);
                }
                if let Some(seed) = config.anchorer_signing_key_seed {
                    return (seed, AnchorerSigningKeyOrigin::Configured);
                }
                // Ephemeral fallback. In production we mix in `boot_nanos`
                // so a soland that boots without a configured seed never
                // signs with the same key twice — this is a security
                // posture choice (no implicit long-lived key on disk).
                //
                // In `development_mode=true` we drop `boot_nanos` and
                // derive the seed deterministically from `service_did`
                // alone. The trade-off: every dev restart kept invalidating
                // every previously-issued sync cursor with
                // `cursor_integrity_invalid` because the freshly-minted
                // key couldn't reproduce yesterday's signature. Stable in
                // dev = `cargo run` doesn't break a connected yougen.
                let mut hasher = Sha256::new();
                hasher.update(b"soland:anchorer-ephemeral:");
                hasher.update(service_did.as_bytes());
                if !config.development_mode {
                    let boot_nanos = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_nanos() as u64)
                        .unwrap_or(0);
                    hasher.update(boot_nanos.to_le_bytes());
                }
                let seed: [u8; 32] = hasher.finalize().into();
                (seed, AnchorerSigningKeyOrigin::Ephemeral)
            })();

        let anchorer_signing_key =
            Arc::new(ArcSwap::from_pointee(SigningKey::from_bytes(&signing_seed)));
        let anchorer_signing_key_origin = Arc::new(Mutex::new(anchorer_signing_key_origin));

        // Per-admin signing keys: build a single
        // [`AdminKeyStore`] for this principal. The application_id
        // mirrors the AnchorerWorker pattern (`soland.<service_did>`) so
        // operators only manage one secret-storage namespace.
        //
        // In `development_mode` we proactively mint an ephemeral seed
        // for every DID listed in `admin_principal_dids` so smoke-tests
        // can call admin endpoints under the operator DID without any
        // out-of-band provisioning step. Production deployments must
        // pre-populate the platform keystore explicitly — admin DIDs
        // without a provisioned key fall back to
        // `service_admin_signer` at signing time with a sticky-warn.
        let admin_app_id = format!("soland.{}", config.service_did);
        let admin_keystore_inner: Box<dyn cokret_sdk::KeyStore> = if config.use_keystore {
            cokret_sdk::platform_default_keystore(&admin_app_id)
        } else {
            Box::new(cokret_sdk::keystore::InMemoryKeyStore::new())
        };
        let admin_keystore =
            cokret_sdk::AdminKeyStore::new(admin_app_id.clone(), admin_keystore_inner);
        if config.development_mode {
            for did_str in &config.admin_principal_dids {
                let Ok(did) = Did::new(did_str.clone()) else {
                    tracing::warn!(%did_str, "skipping admin keystore provision: invalid DID shape");
                    continue;
                };
                let has_key = admin_keystore.has_admin_key(&did).unwrap_or(false);
                if !has_key {
                    let mut seed = [0u8; 32];
                    getrandom_seed(&mut seed);
                    if let Err(error) = admin_keystore.store_admin_key(&did, &seed) {
                        tracing::warn!(%error, %did_str,
                            "failed to provision ephemeral admin signing key");
                    } else {
                        tracing::info!(%did_str,
                            "provisioned ephemeral admin signing key (development_mode)");
                    }
                }
            }
        }
        let admin_keystore = Arc::new(admin_keystore);

        // Space-container/Flow/Morph projections are hydrated from durable
        // persistence in [`AppState::hydrate`] (an explicit async boot step)
        // rather than here, because the persistence store is now async. The
        // write-through path in `routing::events::projection.rs::
        // write_through_projection` keeps these tables in sync as reducer
        // apply mutates the in-memory state.
        let hydrated = ProjectionState::new();

        Self {
            config,
            hlc: ServerHlc::new(&service_did),
            projection: Arc::new(Mutex::new(hydrated)),
            authz: AuthzEngine::new(),
            db,
            persistence,
            object_storage,
            realms: Arc::new(Mutex::new(realms)),
            cross_signing: Arc::new(Mutex::new(cokret_sdk::DeviceManager::new())),
            handle_releases: Arc::new(Mutex::new(BTreeMap::new())),
            account_lifecycle: Arc::new(Mutex::new(BTreeMap::new())),
            erased_actors: Arc::new(Mutex::new(BTreeSet::new())),
            failed_login_attempts: Arc::new(Mutex::new(BTreeMap::new())),
            notification_read_cursors: Arc::new(Mutex::new(BTreeMap::new())),
            sync_cursor_handles: Arc::new(Mutex::new(BTreeMap::new())),
            to_device_position_counter: Arc::new(AtomicI64::new(now.timestamp_micros())),
            consent_cells: Arc::new(Mutex::new(BTreeMap::new())),
            sovereign_deployment: Arc::new(Mutex::new(SovereignDeploymentState {
                upstream_available: true,
                ..Default::default()
            })),
            retention_policies: Arc::new(Mutex::new(BTreeMap::new())),
            retention_tombstones: Arc::new(Mutex::new(BTreeMap::new())),
            federation_block_hints: Arc::new(Mutex::new(BTreeMap::new())),
            organizations: Arc::new(Mutex::new(BTreeMap::new())),
            organization_policies: Arc::new(Mutex::new(BTreeMap::new())),
            space_organizations: Arc::new(Mutex::new(BTreeMap::new())),
            organization_spaces: Arc::new(Mutex::new(BTreeMap::new())),
            space_moderation_policies: Arc::new(Mutex::new(BTreeMap::new())),
            did_resolver,
            move_store: Arc::new(cokret_sdk::state_res::MemoryMoveStore::default()),
            anchor_store: Arc::new(cokret_sdk::state_res::MemoryAnchorStore::default()),
            cell_store: Arc::new(cokret_sdk::state_res::MemoryCellStore::default()),
            // Register all soland LatticeKind impls into the SDK cell
            // registry so the
            // Move/Anchor receive pipeline resolves every spec-declared
            // cell family. Replaces the SDK's built-in defaults (which
            // covered only ~10 generic families).
            cell_registry: Arc::new(crate::reducer::lattice_kinds::build_sdk_cell_registry()),
            // Live event broadcast for ck.events.subscribe streaming.
            // Capacity 1024 events; readers
            // falling behind get `Lagged` and emit `dropped` control frames.
            event_broadcast: broadcast::channel::<EventNotification>(1024).0,
            subscribe_reconnect_gate: Arc::new(Mutex::new(SubscribeReconnectGate::default())),
            anchorer_signing_key,
            anchorer_signing_key_origin,
            admin_keystore,
            // G4.T3 — load verified-profile descriptors at startup. The env
            // var IS the feature flag; absence keeps the dev-mode
            // verified_profiles=[] invariant. See
            // crate::verified_profiles::load_from_env for the file
            // schema and logging policy.
            verified_profiles: crate::verified_profiles::load_from_env(),
            member_identity: Arc::new(Mutex::new(MemberIdentityRegistry::new())),
        }
    }

    /// Touch the (now async) persistence store to finish boot:
    ///   * seed the demo account + Realm metadata when `seed_demo_data` is on,
    ///   * hydrate the Realm directory from persisted `ck.realm.create` events,
    ///   * hydrate Space-container/Flow/Morph projections from durable rows.
    ///
    /// Extracted out of the synchronous `new` constructor so the DB work runs
    /// in an async context (driven from `main`); see the diesel-async
    /// conversion. Safe to call in memory mode — every store read returns an
    /// empty snapshot, so this is a no-op there.
    pub async fn hydrate(&self) {
        let now = chrono::Utc::now();
        if self.config.seed_demo_data {
            let demo_realm_id = "ck:realm:0196419b-0000-7000-8000-000000000000";
            let demo_account = AccountRecord {
                did: "did:web:alice.example".to_owned(),
                handle: "@alice".to_owned(),
                display_name: Some("Alice Example".to_owned()),
                bio: None,
                avatar_url: None,
                created_at: now,
            };
            if let Err(error) = self.persistence.accounts().put(&demo_account).await {
                tracing::warn!(%error, "failed to seed demo account into persistence store");
            }

            let demo_realm_meta = RealmMetaRecord {
                owner: "did:web:alice.example".to_owned(),
                deleted: false,
                discoverability: "public".to_owned(),
                history_visibility: "shared".to_owned(),
                history_sharing_policy: None,
                history_sharing_policy_digest: None,
                preview_policy: None,
                preview_policy_digest: None,
                encryption_profile: None,
                plaintext_visible_services: BTreeSet::new(),
                created_at: now,
                updated_at: now,
            };
            if let Err(error) = self
                .persistence
                .realm_meta()
                .put(demo_realm_id, &demo_realm_meta)
                .await
            {
                tracing::warn!(%error, "failed to seed demo Realm metadata into persistence store");
            }
        }

        // Build the hydrated views off-lock (the async DB reads must not hold
        // a std::sync Mutex guard across `.await`), then merge under a short
        // synchronous critical section.
        let mut realm_updates = RealmDirectoryIndex::new();
        hydrate_realms_from_canonical_events(self.persistence.as_ref(), &mut realm_updates).await;
        {
            let mut realms = self.realms.lock().expect("realms lock");
            for (_, entry) in realm_updates.entries_iter() {
                realms.upsert(entry.clone());
            }
        }

        let mut proj_updates = ProjectionState::new();
        hydrate_projections_from_persistence(self.persistence.as_ref(), &mut proj_updates).await;
        {
            let mut proj = self.projection.lock().expect("projection lock");
            proj.space_containers.extend(proj_updates.space_containers);
            proj.flows.extend(proj_updates.flows);
            proj.morphs.extend(proj_updates.morphs);
        }
    }

    /// MID-1..6 — borrow a clone of the in-memory MemberIdentity
    /// registry, suitable for read-only projection paths (sync roster,
    /// describe payload). Callers that need to mutate state must lock
    /// `self.member_identity` directly.
    pub fn member_identity_registry(&self) -> MemberIdentityRegistry {
        self.member_identity
            .lock()
            .expect("member_identity lock")
            .clone()
    }

    pub fn next_to_device_position(&self) -> i64 {
        let wall = chrono::Utc::now().timestamp_micros();
        loop {
            let current = self.to_device_position_counter.load(Ordering::Relaxed);
            let next = wall.max(current.saturating_add(1));
            match self.to_device_position_counter.compare_exchange(
                current,
                next,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => return next,
                Err(_) => continue,
            }
        }
    }

    pub fn account_lifecycle_record(&self, did: &str) -> AccountLifecycleRecord {
        if self
            .erased_actors
            .lock()
            .expect("erased_actors lock")
            .contains(did)
        {
            return AccountLifecycleRecord {
                state: "erased".to_owned(),
                reason: Some("account_erased".to_owned()),
                changed_by: None,
                changed_at: chrono::Utc::now(),
            };
        }
        self.account_lifecycle
            .lock()
            .expect("account_lifecycle lock")
            .get(did)
            .cloned()
            .unwrap_or_else(|| AccountLifecycleRecord {
                state: "active".to_owned(),
                reason: None,
                changed_by: None,
                changed_at: chrono::Utc::now(),
            })
    }

    pub fn account_lifecycle_state(&self, did: &str) -> String {
        self.account_lifecycle_record(did).state
    }

    pub fn set_account_lifecycle_record(&self, did: &str, record: AccountLifecycleRecord) {
        let mut lifecycle = self
            .account_lifecycle
            .lock()
            .expect("account_lifecycle lock");
        if record.state == "active" {
            lifecycle.remove(did);
        } else {
            lifecycle.insert(did.to_owned(), record);
        }
    }

    /// Return `Some(locked_until)` if the actor is currently locked out by
    /// the failed-login counter. Stale lockouts (`locked_until <= now`)
    /// auto-clear, so the caller can safely treat a `None` return as
    /// "proceed".
    pub fn account_lockout_active_until(&self, did: &str) -> Option<chrono::DateTime<chrono::Utc>> {
        let mut map = self
            .failed_login_attempts
            .lock()
            .expect("failed_login_attempts lock");
        let now = chrono::Utc::now();
        let record = map.get(did).cloned()?;
        match record.locked_until {
            Some(until) if until > now => Some(until),
            Some(_) => {
                // Lockout window expired — clear the record so the actor
                // gets a clean slate on the next attempt.
                map.remove(did);
                None
            }
            None => None,
        }
    }

    /// Record a failed auth attempt against the given actor. Returns the
    /// updated record so the caller can include lockout context in the
    /// audit trail.
    pub fn record_failed_login(&self, did: &str) -> FailedLoginRecord {
        let mut map = self
            .failed_login_attempts
            .lock()
            .expect("failed_login_attempts lock");
        let now = chrono::Utc::now();
        let entry = map.entry(did.to_owned()).or_insert(FailedLoginRecord {
            attempts: 0,
            last_failure_at: now,
            locked_until: None,
        });
        // Reset the rolling counter if the previous failure aged out.
        if now - entry.last_failure_at > ACCOUNT_LOCKOUT_WINDOW {
            entry.attempts = 0;
            entry.locked_until = None;
        }
        entry.attempts = entry.attempts.saturating_add(1);
        entry.last_failure_at = now;
        if entry.attempts >= ACCOUNT_LOCKOUT_THRESHOLD {
            entry.locked_until = Some(now + ACCOUNT_LOCKOUT_DURATION);
        }
        entry.clone()
    }

    /// Clear a successful login's failure history so the rolling counter
    /// doesn't trip on a future stray failure.
    pub fn clear_failed_login(&self, did: &str) {
        self.failed_login_attempts
            .lock()
            .expect("failed_login_attempts lock")
            .remove(did);
    }
}

/// Fill `out` with cryptographically secure random bytes via
/// `rand::OsRng`. Used by both the boot path (one-shot KeyStore mint) and
/// the rotate-signing-key endpoint.
pub(crate) fn getrandom_seed(out: &mut [u8; 32]) {
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(out);
}

/// Read Space-container / Flow / Morph projection rows from durable
/// persistence into the supplied `ProjectionState`. Called at
/// `AppState::new` so restart picks up the lifecycle state the
/// write-through path stamped down on the way in. Unknown state
/// strings or invalid rows are silently skipped (logged at warn) —
/// the in-memory state stays authoritative.
async fn hydrate_projections_from_persistence(
    persistence: &dyn crate::persistence::PersistenceStore,
    proj: &mut ProjectionState,
) {
    use crate::reducer::{
        FlowProjection, MorphProjection, ObjectLifecycleState, SpaceContainerLifecycleState,
        SpaceContainerProjection,
    };

    fn parse_space_container_state(value: &str) -> Option<SpaceContainerLifecycleState> {
        match value {
            "active" => Some(SpaceContainerLifecycleState::Active),
            "archived" => Some(SpaceContainerLifecycleState::Archived),
            "tombstoned" => Some(SpaceContainerLifecycleState::Tombstoned),
            _ => None,
        }
    }
    fn parse_object_state(value: &str) -> Option<ObjectLifecycleState> {
        match value {
            "active" => Some(ObjectLifecycleState::Active),
            "archived" => Some(ObjectLifecycleState::Archived),
            "redacted" => Some(ObjectLifecycleState::Redacted),
            _ => None,
        }
    }

    if let Ok(rows) = persistence
        .space_container_projections()
        .snapshot_all()
        .await
    {
        for record in rows {
            let Some(state) = parse_space_container_state(&record.state) else {
                tracing::warn!(
                    container_space_id = %record.container_space_id,
                    state = %record.state,
                    "skipping space-container projection row with unknown state during hydrate"
                );
                continue;
            };
            proj.space_containers.insert(
                record.container_space_id.clone(),
                SpaceContainerProjection {
                    container_space_id: record.container_space_id,
                    realm_id: record.realm_id,
                    kind: record.kind,
                    title: record.title,
                    parent_ref: record.parent_ref,
                    rank: record.rank,
                    state,
                    state_changed_at: record.state_changed_at,
                    created_by: record.created_by,
                    created_at: record.created_at,
                    updated_by: record.updated_by,
                    updated_at: record.updated_at,
                    // Stream-F (Wave 1B): orphaned flag is reducer-only
                    // bookkeeping; not persisted to the durable mirror
                    // table yet. Replayed durable events will rebuild
                    // it via apply_realm_lifecycle cascade.
                    orphaned: false,
                    // Stream-F (Wave 2C): same story — cross-Realm
                    // parent_ref_locked is also a reducer-only flag
                    // rebuilt by the destroy cascade on replay.
                    parent_ref_locked: false,
                },
            );
        }
    }
    if let Ok(rows) = persistence.flow_projections().snapshot_all().await {
        for record in rows {
            let Some(state) = parse_object_state(&record.state) else {
                tracing::warn!(
                    flow_id = %record.flow_id,
                    state = %record.state,
                    "skipping flow projection row with unknown state during hydrate"
                );
                continue;
            };
            proj.flows.insert(
                record.flow_id.clone(),
                FlowProjection {
                    flow_id: record.flow_id,
                    realm_id: record.realm_id,
                    title: record.title,
                    summary: record.summary,
                    fields: Default::default(),
                    state,
                    state_changed_at: record.state_changed_at,
                    created_by: record.created_by,
                    created_at: record.created_at,
                    updated_by: record.updated_by,
                    updated_at: record.updated_at,
                    scope_circle_id: record.scope_circle_id,
                },
            );
        }
    }
    if let Ok(rows) = persistence.morph_projections().snapshot_all().await {
        for record in rows {
            let Some(state) = parse_object_state(&record.state) else {
                tracing::warn!(
                    morph_id = %record.morph_id,
                    state = %record.state,
                    "skipping morph projection row with unknown state during hydrate"
                );
                continue;
            };
            proj.morphs.insert(
                record.morph_id.clone(),
                MorphProjection {
                    morph_id: record.morph_id,
                    realm_id: record.realm_id,
                    morph_type: record.morph_type,
                    title: record.title,
                    fields: record
                        .fields
                        .as_object()
                        .map(|fields| {
                            fields
                                .iter()
                                .map(|(key, value)| (key.clone(), value.clone()))
                                .collect()
                        })
                        .unwrap_or_default(),
                    schema_refs: record
                        .schema_refs
                        .as_array()
                        .map(|items| {
                            items
                                .iter()
                                .filter_map(serde_json::Value::as_str)
                                .map(ToOwned::to_owned)
                                .collect()
                        })
                        .unwrap_or_default(),
                    facets: record
                        .facets
                        .as_array()
                        .map(|items| {
                            items
                                .iter()
                                .filter_map(serde_json::Value::as_str)
                                .map(ToOwned::to_owned)
                                .collect()
                        })
                        .unwrap_or_default(),
                    versions: serde_json::from_value(record.versions).unwrap_or_default(),
                    state,
                    state_changed_at: record.state_changed_at,
                    created_by: record.created_by,
                    created_at: record.created_at,
                    updated_by: record.updated_by,
                    updated_at: record.updated_at,
                },
            );
        }
    }
}

async fn hydrate_realms_from_canonical_events(
    persistence: &dyn crate::persistence::PersistenceStore,
    realms: &mut RealmDirectoryIndex,
) {
    let Ok(events) = persistence.events().snapshot_all().await else {
        return;
    };
    for record in events {
        if record.kind == "ck.realm.create" {
            hydrate_realm_create_event(persistence, realms, &record).await;
        } else if matches!(
            record.kind.as_str(),
            "ck.realm.history_visibility"
                | "ck.realm.history_sharing_policy"
                | "ck.realm.preview_policy"
        ) {
            hydrate_realm_policy_event(persistence, &record).await;
        }
    }
}

async fn hydrate_realm_create_event(
    persistence: &dyn crate::persistence::PersistenceStore,
    realms: &mut RealmDirectoryIndex,
    record: &CanonicalEventRecord,
) {
    let payload_object = record
        .envelope
        .get("payload")
        .and_then(|payload| payload.get("object"));
    let Some(realm_id) = record
        .envelope
        .get("realm_id")
        .and_then(Value::as_str)
        .or_else(|| {
            payload_object
                .and_then(|object| object.get("id"))
                .and_then(Value::as_str)
        })
        .or_else(|| record.envelope.get("space_id").and_then(Value::as_str))
        .or(record.realm_id.as_deref())
        .map(normalize_persisted_realm_id)
    else {
        return;
    };
    let Ok(realm_id) = RealmId::new(realm_id.clone()) else {
        tracing::warn!(realm_id = %realm_id, "skipping persisted realm.create with invalid realm_id");
        return;
    };
    let Ok(actor) = Did::new(record.actor_id.clone()) else {
        tracing::warn!(actor = %record.actor_id, "skipping persisted realm.create with invalid actor");
        return;
    };
    let title = payload_object
        .and_then(|object| object.get("title"))
        .and_then(Value::as_str)
        .unwrap_or(realm_id.as_str());
    let summary = payload_object
        .and_then(|object| object.get("summary"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let discoverability = payload_object
        .and_then(|object| object.get("default_discoverability"))
        .and_then(Value::as_str)
        .unwrap_or("invite_only")
        .to_owned();
    let history_visibility = payload_object
        .and_then(|object| object.get("history_visibility"))
        .and_then(Value::as_str)
        .unwrap_or("shared")
        .to_owned();
    let encryption_profile = payload_object
        .and_then(|object| object.get("encryption_profile"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let history_sharing_policy = payload_object
        .and_then(|object| object.get("history_sharing_policy"))
        .cloned();
    let history_sharing_policy_digest = history_sharing_policy
        .as_ref()
        .and_then(canonical_value_digest);
    let preview_policy = payload_object
        .and_then(|object| object.get("preview_policy"))
        .cloned();
    let preview_policy_digest = preview_policy.as_ref().and_then(canonical_value_digest);
    let plaintext_visible_services = record
        .envelope
        .get("payload")
        .and_then(|payload| payload.get("plaintext_visible_services"))
        .or_else(|| payload_object.and_then(|object| object.get("plaintext_visible_services")))
        .and_then(Value::as_array)
        .map(|services| {
            services
                .iter()
                .filter_map(|service| service.as_str().map(ToOwned::to_owned))
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();

    let mut entry = RealmDirectoryEntry::new(realm_id.clone(), title);
    entry.description = summary.clone();
    entry.public = discoverability == "public";
    entry.members.insert(actor);
    realms.upsert(entry);

    let meta = RealmMetaRecord {
        owner: record.actor_id.clone(),
        deleted: false,
        discoverability,
        history_visibility,
        history_sharing_policy,
        history_sharing_policy_digest,
        preview_policy,
        preview_policy_digest,
        encryption_profile,
        plaintext_visible_services,
        created_at: record.received_at,
        updated_at: record.received_at,
    };
    if let Err(error) = persistence.realm_meta().put(realm_id.as_str(), &meta).await {
        tracing::warn!(%error, realm_id = %realm_id, "failed to hydrate persisted realm meta");
    }
}

async fn hydrate_realm_policy_event(
    persistence: &dyn crate::persistence::PersistenceStore,
    record: &CanonicalEventRecord,
) {
    let Some(realm_id) = event_record_realm_id(record) else {
        return;
    };
    let Ok(Some(mut meta)) = persistence.realm_meta().get(&realm_id).await else {
        return;
    };
    let Some(payload) = record.envelope.get("payload") else {
        return;
    };
    match record.kind.as_str() {
        "ck.realm.history_visibility" => {
            if let Some(value) = payload.get("value").and_then(Value::as_str) {
                meta.history_visibility = value.to_owned();
            }
        }
        "ck.realm.history_sharing_policy" => {
            if let Some(value) = payload.get("value") {
                meta.history_sharing_policy = Some(value.clone());
                meta.history_sharing_policy_digest = canonical_value_digest(value);
            }
        }
        "ck.realm.preview_policy" => {
            if let Some(value) = payload.get("value") {
                meta.preview_policy = Some(value.clone());
                meta.preview_policy_digest = canonical_value_digest(value);
            }
        }
        _ => {}
    }
    meta.updated_at = record.received_at;
    if let Err(error) = persistence.realm_meta().put(&realm_id, &meta).await {
        tracing::warn!(%error, realm_id = %realm_id, "failed to hydrate Realm policy event");
    }
}

fn event_record_realm_id(record: &CanonicalEventRecord) -> Option<String> {
    record
        .envelope
        .get("realm_id")
        .and_then(Value::as_str)
        .or(record.realm_id.as_deref())
        .map(normalize_persisted_realm_id)
}

fn canonical_value_digest(value: &Value) -> Option<String> {
    let bytes = cokret_sdk::canonical::canonical_json_bytes(value).ok()?;
    Some(cokret_sdk::canonical::sha256_digest(bytes))
}

fn normalize_persisted_realm_id(id: &str) -> String {
    id.strip_prefix("ck:space:")
        .map(|suffix| format!("ck:realm:{suffix}"))
        .unwrap_or_else(|| id.to_owned())
}
