use std::collections::BTreeMap;

use arkret_core::{CrossSigningPublish, CrossSigningResetPayload, DeviceId, Did, Error, Result};
use chrono::{DateTime, Utc};

/// Server-side cross-signing projection.
///
/// This stores only accepted publish/reset lineage and device revocations. It
/// deliberately excludes client device lists, verification challenges,
/// to-device queues, and key-backup state.
#[derive(Clone, Debug, Default)]
pub struct CrossSigningRegistry {
    publishes: BTreeMap<Did, CrossSigningPublish>,
    generation_high_water: BTreeMap<Did, u64>,
    revoked_devices: BTreeMap<Did, BTreeMap<DeviceId, DateTime<Utc>>>,
}

impl CrossSigningRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn current_cross_signing(&self, principal: &Did) -> Option<&CrossSigningPublish> {
        self.publishes.get(principal)
    }

    pub fn record_cross_signing_publish(&mut self, publish: CrossSigningPublish) -> Result<()> {
        publish.validate_structure()?;
        let principal = publish.principal_id.clone();
        let current_generation = self
            .generation_high_water
            .get(&principal)
            .copied()
            .unwrap_or(0);
        if publish.expected_previous_generation != current_generation {
            return Err(Error::Protocol(format!(
                "cross_signing publish expected_previous_generation {} does not match accepted {} (cas_conflict)",
                publish.expected_previous_generation, current_generation
            )));
        }
        if publish.generation.get() != current_generation + 1 {
            return Err(Error::Protocol(format!(
                "cross_signing publish generation {} must equal current {} + 1 (cas_conflict)",
                publish.generation, current_generation
            )));
        }
        self.generation_high_water
            .insert(principal.clone(), publish.generation.get());
        self.publishes.insert(principal, publish);
        Ok(())
    }

    pub fn record_cross_signing_reset(&mut self, reset: &CrossSigningResetPayload) -> Result<()> {
        reset.validate_structure()?;
        let principal = reset.principal_id();
        let current = self.publishes.get(principal).ok_or_else(|| {
            Error::Protocol(
                "cannot reset cross-signing: no current publish accepted for principal".to_owned(),
            )
        })?;
        if reset.previous_generation() != current.generation.get() {
            return Err(Error::Protocol(format!(
                "cross_signing reset previous_generation {} does not match accepted {}",
                reset.previous_generation(),
                current.generation
            )));
        }
        self.publishes.remove(principal);
        self.generation_high_water
            .insert(principal.clone(), reset.new_generation());
        if let Some(device_ids) = reset.revoked_device_ids() {
            let revoked = self.revoked_devices.entry(principal.clone()).or_default();
            let now = Utc::now();
            for device_id in device_ids {
                revoked.insert(device_id.clone(), now);
            }
        }
        Ok(())
    }

    pub fn is_device_revoked(&self, principal: &Did, device_id: &DeviceId) -> bool {
        self.revoked_devices
            .get(principal)
            .is_some_and(|devices| devices.contains_key(device_id))
    }
}
