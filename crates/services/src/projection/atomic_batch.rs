//! All-or-nothing batch application of an ordered accepted-Event run.
//!
//! The Station admits an Event, appends its authority `RealmCommit`, installs
//! the product projection and enqueues the federation outbox rows inside one
//! database transaction. Multi-Event atomicity therefore belongs to that
//! transaction, not to a commit object that carries several Events: a
//! `RealmCommit` carries exactly one `event_ref`.
//!
//! The in-memory projection has to match that boundary. Applying a run
//! operation by operation against the live state would leave a prefix
//! installed when a later operation is rejected, which is a state the durable
//! transaction can never produce. This module therefore folds the run over a
//! private clone and publishes it only once every operation is accepted.

use super::*;

impl ProjectionService {
    /// Fold an ordered run of accepted operations and publish the result only
    /// if every one of them is accepted.
    ///
    /// A rejection returns its reducer reason and leaves the live projection
    /// byte-identical to what it was before the call.
    pub fn apply_operations_atomic(
        &self,
        operations: &[&Operation],
        hlc: &ServerHlc,
    ) -> Result<Vec<ProjectionEffectView>, String> {
        let mut live = self.write_state();
        let mut staged = live.clone();
        let mut effects = Vec::with_capacity(operations.len());
        for operation in operations {
            let effect = staged.apply_projected(operation, hlc);
            match &effect {
                ProjectionEffect::Rejected { reason }
                | ProjectionEffect::PendingReplayQueued { reason, .. } => {
                    return Err(reason.clone());
                }
                _ => {}
            }
            effects.push(effect.into());
        }
        *live = staged;
        Ok(effects)
    }
}
