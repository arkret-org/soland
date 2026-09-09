//! Bounded process-local caches for independently expiring signed statements.

use std::collections::BTreeMap;
use std::sync::Arc;

use arkret_models_identity::{AgentAuthorityStateLease, ControllerAccountGateAttestation};
use arkret_wire::{DidCoreId, DidUrl, Hash};
use chrono::{DateTime, Utc};
use parking_lot::Mutex;

type GateSlot = Arc<tokio::sync::Mutex<Option<ControllerAccountGateAttestation>>>;

#[derive(Default)]
pub(crate) struct AgentEvidenceCache {
    gates: Mutex<BTreeMap<(DidCoreId, DidCoreId, DidCoreId), GateSlot>>,
    pub(crate) state_leases: Mutex<BTreeMap<(Hash, DidUrl), AgentAuthorityStateLease>>,
    pub(crate) verified_contexts:
        Mutex<BTreeMap<(DidCoreId, DidUrl), arkret::VerifiedAgentCurrentContext>>,
}

impl AgentEvidenceCache {
    pub(crate) fn gate_slot(
        &self,
        key: (DidCoreId, DidCoreId, DidCoreId),
        now: DateTime<Utc>,
    ) -> GateSlot {
        let mut gates = self.gates.lock();
        if let Some(slot) = gates.get(&key) {
            return slot.clone();
        }
        gates.retain(|_, slot| {
            Arc::strong_count(slot) > 1
                || slot.try_lock().map_or(true, |gate| {
                    gate.as_ref().is_some_and(|gate| now < gate.expires_at)
                })
        });
        let slot = Arc::new(tokio::sync::Mutex::new(None));
        if gates.len() < 4096 {
            gates.insert(key, slot.clone());
        }
        slot
    }
}
