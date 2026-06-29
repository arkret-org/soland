//! G3.S9 — Bot / ghost actor registry (persistence-backed view).
//!
//! Bot and ghost actors are second-class identities tied to a primary actor's
//! authority (the applet controller). Canonical provisioning happens through
//! `ck.self.applet.command.install` / `ck.applet.registration`; the durable
//! source of truth is the `applet_registrations` table (`persistence::applets`,
//! materialised as [`AppletRecord`]). Per
//! `extensions/applet-integration.md` §3–§5:
//!
//! - A **bot actor** is a stable per-applet DID. Created when the applet install
//!   completes (`applet_registrations.bot_actor_id`); lives until the applet is
//!   revoked (`applet_registrations.revoked_at`).
//! - A **ghost actor** is a per-external-user DID minted by the applet to
//!   represent an external user inside the portal realm. Recorded as a row in
//!   the applet record's `ghosts` array; the `kind` discriminator differs.
//!
//! SOL-HYG-01 — durability / horizontal scale.
//! This module used to keep bot/ghost liveness + revocation in a process-local
//! `static Mutex<Vec<BotActor>>`, which did not survive a restart and did not
//! propagate across replicas. That shadow state was redundant: every
//! registration and revocation is already persisted to `applet_registrations`
//! by the install / revoke paths before the registry was touched, and nothing on
//! the production path ever read the registry back. The registry is now a thin
//! **read view** that derives [`BotActor`] rows directly from the persisted
//! applet records, so liveness + revocation are durable and consistent across
//! replicas with a single source of truth.
//!
//! TODO(G3.S9-followup): bind bot/ghost provisioning to the verified manifest's
//! `applet_id`; emit `ck.identity.accountability_grant` events so the
//! accountability chain is queryable via the standard DID Document fetch (the
//! ghost provisioning path already builds these via
//! `applet_bridge::build_ghost_accountability_grant_event`; bot-actor inception
//! grants remain a follow-up).

use cokret_sdk::Did;
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};

use super::applet_bridge::{applet_display_name, applet_records};
use crate::error::AppError;
use crate::state::AppState;

/// Discriminator for [`BotActor::kind`].
pub const KIND_BOT: &str = "bot";
pub const KIND_GHOST: &str = "ghost";

/// On-wire representation of a bot or ghost actor, derived from a persisted
/// applet record.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct BotActor {
    pub did: String,
    pub name: String,
    /// `"bot"` or `"ghost"`. We don't lean on an enum here so the wire
    /// stays open to future kinds without a breaking change in the JSON
    /// schema.
    pub kind: String,
    pub owner_actor_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// List non-revoked bot and ghost actors owned by `owner_actor_id`, derived
/// from the durable applet records. A bot actor is owned by the applet's
/// `owner_actor_id`; a ghost actor is owned by the same actor as its parent
/// applet. Revoked applets (and revoked ghosts) are skipped.
pub async fn list_bots_owned_by(
    state: &AppState,
    owner_actor_id: &str,
) -> Result<Vec<BotActor>, AppError> {
    let mut bots = Vec::new();
    for record in applet_records(state).await? {
        if record.owner_actor_id != owner_actor_id {
            continue;
        }
        let applet_revoked = record.revoked_at.is_some();
        if !applet_revoked {
            bots.push(BotActor {
                did: record.bot_actor_id.clone(),
                name: applet_display_name(&record.manifest)
                    .unwrap_or_else(|| record.namespace.clone()),
                kind: KIND_BOT.to_owned(),
                owner_actor_id: record.owner_actor_id.clone(),
                created_at: record.registered_at,
                revoked_at: None,
            });
        }
        for ghost in &record.ghosts {
            if applet_revoked || ghost.revoked_at.is_some() {
                continue;
            }
            bots.push(BotActor {
                did: ghost.ghost_actor_id.clone(),
                name: ghost
                    .display_name
                    .clone()
                    .unwrap_or_else(|| ghost.external_id.clone()),
                kind: KIND_GHOST.to_owned(),
                owner_actor_id: record.owner_actor_id.clone(),
                created_at: ghost.created_at,
                revoked_at: None,
            });
        }
    }
    Ok(bots)
}

/// Validate that an extension actor DID is a bare DID scalar (no DID URL
/// fragment) and well-formed, before it is recorded against an applet.
#[allow(dead_code)]
pub(super) fn validate_extension_actor_did(did: &str) -> Result<(), AppError> {
    if did.contains('#') {
        return Err(AppError::invalid_param(
            "bot and ghost actor DID must be a DID scalar without fragment",
        )
        .with_wire_code("schema_violation"));
    }
    Did::new(did.to_owned()).map(|_| ()).map_err(|error| {
        AppError::invalid_param(format!("bot or ghost actor DID is invalid: {error}"))
            .with_wire_code("schema_violation")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bot_register_rejects_did_url_fragment() {
        let err = validate_extension_actor_did("did:web:alice.example#agent").unwrap_err();
        assert_eq!(err.wire_code(), "schema_violation");
    }

    #[test]
    fn bot_did_scalar_is_accepted() {
        validate_extension_actor_did("did:web:alice.example").expect("bare DID scalar is valid");
    }
}
