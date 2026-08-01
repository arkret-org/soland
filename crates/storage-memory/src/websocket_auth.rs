use soland_storage::{
    PersistenceError, WebsocketAuthChallengeRecord, WebsocketAuthReplayRecord, WebsocketAuthStore,
};

use super::{Arc, BTreeMap, BTreeSet, Mutex, PersistenceResult, Utc, async_trait};

/// In-memory `ak.profile.binding.websocket.v1` challenge store + replay ledger.
///
/// Mirrors the two Pg tables on the same keys. The single mutex around both
/// maps is what makes `consume_challenge` the one atomic step §3.1 requires:
/// a concurrent second `authenticate` cannot observe the challenge unconsumed
/// after the ledger key landed.
pub(crate) struct MemoryWebsocketAuthStore {
    state: Arc<Mutex<WebsocketAuthState>>,
}

#[derive(Default)]
struct WebsocketAuthState {
    challenges: BTreeMap<(String, String), WebsocketAuthChallengeRecord>,
    replay_ledger: BTreeMap<(String, String, String), WebsocketAuthReplayRecord>,
}

impl MemoryWebsocketAuthStore {
    pub(crate) fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(WebsocketAuthState::default())),
        }
    }
}

#[async_trait]
impl WebsocketAuthStore for MemoryWebsocketAuthStore {
    async fn prepare_challenge(
        &self,
        record: &WebsocketAuthChallengeRecord,
    ) -> PersistenceResult<()> {
        let mut state = self.state.lock();
        let key = (record.connection_id.clone(), record.nonce.clone());
        if state.challenges.contains_key(&key) {
            return Err(PersistenceError::Conflict(
                "websocket challenge already exists for this connection and nonce".to_owned(),
            ));
        }
        state.challenges.insert(key, record.clone());
        Ok(())
    }

    async fn get_challenge(
        &self,
        connection_id: &str,
        nonce: &str,
    ) -> PersistenceResult<Option<WebsocketAuthChallengeRecord>> {
        let state = self.state.lock();
        Ok(state
            .challenges
            .get(&(connection_id.to_owned(), nonce.to_owned()))
            .cloned())
    }

    async fn replay_ledger_contains(
        &self,
        cnf_jkt: &str,
        jti: &str,
        proof_context: &str,
    ) -> PersistenceResult<bool> {
        let state = self.state.lock();
        Ok(state.replay_ledger.contains_key(&(
            cnf_jkt.to_owned(),
            jti.to_owned(),
            proof_context.to_owned(),
        )))
    }

    async fn consume_challenge(
        &self,
        connection_id: &str,
        nonce: &str,
        replay: &WebsocketAuthReplayRecord,
    ) -> PersistenceResult<bool> {
        let mut state = self.state.lock();
        let ledger_key = (
            replay.cnf_jkt.clone(),
            replay.jti.clone(),
            replay.proof_context.clone(),
        );
        if state.replay_ledger.contains_key(&ledger_key) {
            return Ok(false);
        }
        let Some(challenge) = state
            .challenges
            .get_mut(&(connection_id.to_owned(), nonce.to_owned()))
        else {
            return Ok(false);
        };
        if challenge.consumed {
            return Ok(false);
        }
        challenge.consumed = true;
        state.replay_ledger.insert(ledger_key, replay.clone());
        Ok(true)
    }

    async fn prune_expired(&self, now: chrono::DateTime<Utc>) -> PersistenceResult<usize> {
        let mut state = self.state.lock();
        let stale_challenges: BTreeSet<_> = state
            .challenges
            .iter()
            .filter(|(_, record)| record.retain_until <= now)
            .map(|(key, _)| key.clone())
            .collect();
        let stale_ledger: BTreeSet<_> = state
            .replay_ledger
            .iter()
            .filter(|(_, record)| record.retain_until <= now)
            .map(|(key, _)| key.clone())
            .collect();
        for key in &stale_challenges {
            state.challenges.remove(key);
        }
        for key in &stale_ledger {
            state.replay_ledger.remove(key);
        }
        Ok(stale_challenges.len() + stale_ledger.len())
    }
}
