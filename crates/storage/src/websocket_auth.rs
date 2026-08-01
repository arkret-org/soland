use super::{PersistenceResult, Utc, async_trait};

/// One single-use `challenge_dpop_session_v1` challenge
/// (`zh/sync/websocket-binding.md` §3.1).
///
/// The service writes this row atomically **before** it sends the `challenge`
/// frame. `connection_id` and the socket `Origin` are bound here, not inside
/// the proof: the profile forbids carrying them as private JWT claims, so this
/// record is the only thing that ties a proof to the socket it arrived on.
///
/// Durable and shared: §3.1 requires multi-instance deployments to use one
/// consistent state, so a process-local map is not an acceptable backing.
#[derive(Clone, Debug, PartialEq)]
pub struct WebsocketAuthChallengeRecord {
    pub connection_id: String,
    pub nonce: String,
    pub canonical_origin: String,
    pub canonical_base_url: String,
    pub issued_at: chrono::DateTime<Utc>,
    pub expires_at: chrono::DateTime<Utc>,
    pub consumed: bool,
    /// `expires_at + 300s` at least, so a replay stays distinguishable from an
    /// unknown challenge for the whole retention window.
    pub retain_until: chrono::DateTime<Utc>,
}

/// One replay-ledger key `(cnf.jkt, jti, context)`.
#[derive(Clone, Debug, PartialEq)]
pub struct WebsocketAuthReplayRecord {
    pub cnf_jkt: String,
    pub jti: String,
    pub proof_context: String,
    pub consumed_at: chrono::DateTime<Utc>,
    pub retain_until: chrono::DateTime<Utc>,
}

/// Durable challenge + replay-ledger state for the WebSocket binding.
#[async_trait]
pub trait WebsocketAuthStore: Send + Sync {
    /// Write a fresh challenge. Fails if `(connection_id, nonce)` already
    /// exists: a challenge is minted once and never rewritten.
    async fn prepare_challenge(
        &self,
        record: &WebsocketAuthChallengeRecord,
    ) -> PersistenceResult<()>;

    /// Read the stored challenge, including a consumed one — the retention
    /// window exists so replay and unknown stay distinguishable.
    async fn get_challenge(
        &self,
        connection_id: &str,
        nonce: &str,
    ) -> PersistenceResult<Option<WebsocketAuthChallengeRecord>>;

    /// True when the ledger already holds this key.
    async fn replay_ledger_contains(
        &self,
        cnf_jkt: &str,
        jti: &str,
        proof_context: &str,
    ) -> PersistenceResult<bool>;

    /// Mark the challenge consumed and write the replay-ledger key in **one**
    /// atomic step (§3.1). Returns `false` when either half was already taken,
    /// which is the replay outcome; no partial session may be established on
    /// that path.
    async fn consume_challenge(
        &self,
        connection_id: &str,
        nonce: &str,
        replay: &WebsocketAuthReplayRecord,
    ) -> PersistenceResult<bool>;

    /// TTL sweep for both tables.
    async fn prune_expired(&self, now: chrono::DateTime<Utc>) -> PersistenceResult<usize>;
}
