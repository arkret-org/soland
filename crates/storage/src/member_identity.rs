use super::{PersistenceResult, Value, async_trait};

/// Cell subject key for the member-identity registry. Mirrors the composite
/// `(payload.realm_id, payload.actor_id, payload.segment)` cell subject from
/// `event-kind-registry.json`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MemberIdentitySubjectKey {
    pub realm_id: String,
    pub actor_id: String,
    pub segment: String,
}

/// One replacement edge resolved from `payload.replaces[]`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MemberIdentityReplacementEdge {
    pub event_id: String,
    pub payload_digest: String,
}

/// One stored `ak.member.identity.update` event.
#[derive(Clone, Debug, PartialEq)]
pub struct MemberIdentityEventRecord {
    pub event_id: String,
    pub subject: MemberIdentitySubjectKey,
    /// SHA-256 over RFC 8785 JCS canonical JSON of the full
    /// `payload.identity_payload` carrier object (the value goes into
    /// any subsequent event's `payload.replaces[].payload_digest`).
    pub payload_digest: String,
    /// `payload.replaces[]` references as observed on the wire. The
    /// effective-set filter matches each edge's `payload_digest` against the
    /// referenced event's stored `payload_digest` at projection time
    /// (mismatched / cross-subject references are dropped as no-op edges per
    /// MID-2).
    pub replaces: Vec<MemberIdentityReplacementEdge>,
    /// Original Event envelope as received. MID-5: soland MUST store the
    /// envelope verbatim; no query-time re-encryption, no projection
    /// rewrite.
    pub raw_event: Value,
}

/// Local handle-claim evidence record, keyed by claim `subject`. Sources are
/// deliberately local-only: directory-issued signed claims and handle-claim
/// envelopes carried by accepted identity events.
#[derive(Clone, Debug, PartialEq)]
pub struct HandleClaimEvidenceRecord {
    pub digest: String,
    pub subject_id: String,
    pub issuer: String,
    pub issuer_service_id: Option<String>,
    pub audience: Option<String>,
    pub binding_state: String,
    pub visibility: Option<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub revoked: bool,
    pub envelope: Value,
}

/// Durable member-identity registry store (mirror of the
/// `member_identity_events` + `member_identity_handle_claims` tables).
///
/// The in-memory `MemberIdentityRegistry` in `soland-http` stays the
/// synchronous read/projection surface; writers go through this store first
/// and `AppState::hydrate` rebuilds the registry from it on startup, so the
/// MID effective-set digests and roster projection survive restart.
#[async_trait]
pub trait MemberIdentityStore: Send + Sync {
    /// Idempotent upsert keyed by `event_id` (replay re-projection lands the
    /// same row again).
    async fn put_event(&self, record: &MemberIdentityEventRecord) -> PersistenceResult<()>;
    /// Full event snapshot for startup hydration.
    async fn snapshot_events(&self) -> PersistenceResult<Vec<MemberIdentityEventRecord>>;
    /// Idempotent upsert keyed by `(subject_id, digest)`.
    async fn put_handle_claim(&self, record: &HandleClaimEvidenceRecord) -> PersistenceResult<()>;
    /// Drop every cached claim for one subject; returns the number removed.
    async fn delete_handle_claims_for_subject(&self, subject_id: &str) -> PersistenceResult<usize>;
    /// Full handle-claim snapshot for startup hydration.
    async fn snapshot_handle_claims(&self) -> PersistenceResult<Vec<HandleClaimEvidenceRecord>>;
}
