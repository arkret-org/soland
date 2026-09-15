//! Applet-managed delegated device authority.
//!
//! `device-lifecycle.md` 5.2.3 gives an Applet-managed Bot or Ghost the only
//! device-authorization branch it can reach, and 15 binds the resulting device
//! to the exact install that created the principal. Both rules need state the
//! SDK cannot hold: whether the principal's provision and
//! `applet_managed_control` PCR genesis are accepted, and whether that install
//! is still active.
//!
//! Every answer here comes from the same durable pair the install transaction
//! writes: the per-`applet_id` managed-identity winner row, which freezes the
//! accepted `ak.applet.managed_actor.provision` and PCR genesis Events, and the
//! per-`(applet_id, effective_scope)` installation row, which carries the 4b
//! revoke fence. The PCR device directory is deliberately not consulted -- when
//! the delegated authorize is admitted that directory is still empty, which is
//! exactly why 5.3 resolves the signer from the provisioned current resolution
//! cell instead.

use arkret_wire::{AppletId, DidCoreId, EventId, RealmId, ScopeRef};
use soland_http::error::AppError;

use super::record::applet_records;
use super::types::AppletRecord;
use crate::state::AppState;

/// The exact Applet install that provisioned one Applet-managed principal.
pub struct ManagedPrincipalAuthority {
    /// `applet_id` the delegated device's payload MUST carry verbatim.
    pub applet_id: AppletId,
    /// Scope half of the install's unique `(applet_id, effective_scope)` key.
    pub effective_scope: ScopeRef,
    /// The principal's own `applet_managed_control` PCR, the only Realm a
    /// delegated `ak.device.authorize` may be submitted to.
    pub principal_control_realm_id: RealmId,
    /// Accepted `ak.applet.managed_actor.provision` that created the principal.
    pub provision_event_id: EventId,
    /// Accepted `applet_managed_control` `ak.realm.create` genesis.
    pub pcr_genesis_event_id: EventId,
    /// `applet-integration.md` 4b revoke fence, globally or for this install.
    pub fenced: bool,
}

/// 4b fence state of one exact install.
///
/// The global identity fence and the per-scope revoke are both fences: the
/// first covers the Applet's last active install being revoked, the second this
/// exact `(applet_id, effective_scope)` row. `revoking` is already fenced --
/// 4b fences future writes from the first accepted revoke Event, not from saga
/// completion.
fn install_fenced(record: &AppletRecord) -> bool {
    record.identity.globally_fenced_at.is_some()
        || record.revoked_at.is_some()
        || !matches!(record.status.as_str(), "installed" | "partially_installed")
}

/// Resolve the exact install that provisioned `principal_id`, or `None` when
/// the principal is not Applet-managed at all.
pub async fn managed_principal_authority(
    state: &AppState,
    principal_id: &DidCoreId,
) -> Result<Option<ManagedPrincipalAuthority>, AppError> {
    for record in applet_records(state).await? {
        if record.bot_actor_id.signing_principal_id() == principal_id {
            // 4b freezes the managed-Bot anchors at the first accepted install
            // and makes every later scope reuse them, so several installation
            // rows name this same Bot. Only the row whose effective scope is
            // the frozen initial scope is the install that created it; another
            // scope of the same Applet is a different install and MUST NOT
            // stand in for its fence.
            if record.effective_scope != record.initial_effective_scope {
                continue;
            }
            return Ok(Some(ManagedPrincipalAuthority {
                applet_id: record.applet_id.clone(),
                effective_scope: record.effective_scope.clone(),
                principal_control_realm_id: record.bot_principal_control_realm_id.clone(),
                provision_event_id: record.bot_actor_provision_event.event_id.clone(),
                pcr_genesis_event_id: record.bot_pcr_genesis_event.event_id.clone(),
                fenced: install_fenced(&record),
            }));
        }
        // A Ghost is provisioned into exactly one installation row, so the row
        // holding it is its exact install by construction.
        if let Some(ghost) = record
            .ghosts
            .iter()
            .find(|ghost| ghost.ghost_actor_id.signing_principal_id() == principal_id)
        {
            return Ok(Some(ManagedPrincipalAuthority {
                applet_id: record.applet_id.clone(),
                effective_scope: record.effective_scope.clone(),
                principal_control_realm_id: ghost.principal_control_realm_id(),
                provision_event_id: ghost.managed_actor_provision_event.event_id.clone(),
                pcr_genesis_event_id: ghost.pcr_genesis_event.event_id.clone(),
                fenced: install_fenced(&record),
            }));
        }
    }
    Ok(None)
}

/// `device-lifecycle.md` 15 install revoke fence, ANDed into the MLS surfaces.
///
/// An Applet-managed principal can only ever hold delegated devices: its
/// `applet_managed_control` genesis is forbidden from carrying a founding
/// device, `accepted_device` needs an accepted device it can never obtain
/// first, `pcr_recovery` is closed to it, and a delegated device MUST NOT
/// authorize another one. So "this device belongs to an Applet-managed
/// principal" is exactly "this is a delegated device", and the fence follows
/// the principal without a second device-to-install mapping table -- which is
/// what 5.2.3 means by making `applet_id` the revocation fence carrier.
///
/// A principal that is not Applet-managed is unaffected.
pub async fn ensure_delegated_device_not_fenced(
    state: &AppState,
    principal_id: &DidCoreId,
) -> Result<(), AppError> {
    let Some(authority) = managed_principal_authority(state, principal_id).await? else {
        return Ok(());
    };
    if authority.fenced {
        return Err(AppError::capability_denied(
            "Applet install has been revoked; its delegated device may not publish KeyPackages, \
             enter a group or sign durable receipts",
        )
        .with_wire_code(arkret_wire::ErrorCode::APPLET_REVOKED));
    }
    Ok(())
}
