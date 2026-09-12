use super::*;

impl ProjectionService {
    pub async fn reserve_signing_body(
        &self,
        body: &arkret_wire::UnsignedSeal,
        suite: arkret_canonical::DigestSuite,
    ) -> StoreResult<arkret_wire::UnsignedSeal> {
        self.seal_store().reserve_signing_body(body, suite).await
    }

    pub async fn signing_body(
        &self,
        realm: &RealmId,
        sequence: u64,
    ) -> StoreResult<Option<arkret_wire::UnsignedSeal>> {
        self.seal_store().signing_body(realm, sequence).await
    }

    /// Stage the entire ordered batch before installing any domain effect.
    /// The caller supplies only Events already committed by an exact Seal unit.
    pub fn apply_operations_with_effects_atomic(
        &self,
        operations: &[(&Operation, &[ProjectedCellWrite])],
        hlc: &ServerHlc,
    ) -> Result<Vec<ProjectionEffectView>, String> {
        let _authority_guard = self.history_authority_view_cas_guard();
        let registry = soland_domain::reducer::state_model_kinds::default_cell_family_registry();
        let mut live = self.state.lock();
        let mut staged = live.clone();
        let mut effects = Vec::with_capacity(operations.len());
        for (operation, writes) in operations {
            let effect = staged.apply_via_state_model_registry(operation, writes, hlc, &registry);
            match &effect {
                ProjectionEffect::Rejected { reason }
                | ProjectionEffect::PendingReplayQueued { reason, .. } => {
                    return Err(reason.clone());
                }
                // Registered safety cells without an inline domain mirror use
                // Ignored here; their effects are already in the Seal store.
                _ => {}
            }
            effects.push(effect.into());
        }
        *live = staged;
        Ok(effects)
    }
}
