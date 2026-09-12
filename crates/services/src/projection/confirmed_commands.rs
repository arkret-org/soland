use super::*;

impl ProjectionService {
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
                ProjectionEffect::Ignored => {
                    return Err("committed command projection was ignored".into());
                }
                _ => {}
            }
            effects.push(effect.into());
        }
        *live = staged;
        Ok(effects)
    }
}
