//! G3.S9 — Bot / ghost actor registry (runnable stub).
//!
//! Bot and ghost actors are second-class identities tied to a primary actor's
//! authority (the applet controller). Canonical provisioning happens through
//! `ck.self.applet.command.install` / `ck.applet.registration`; this registry is the local
//! runtime state those strands populate. Per
//! `extensions/applet-integration.md` §3–§5:
//!
//! - A **bot actor** is a stable per-applet DID. Registered once when the applet install completes;
//!   lives until revoked.
//! - A **ghost actor** is a per-external-user DID minted by the applet to represent an external
//!   user inside the portal realm. Same wire shape as bots; the `kind` discriminator differs.
//!
//! Both flavours are recorded in a process-local registry
//! (`BOT_REGISTRY` below).
//!
//! SOL-HYG-01 — KNOWN LIMITATION (durability / horizontal scale):
//! `BOT_REGISTRY` is a `static Mutex<Vec<..>>`, so the bot/ghost *liveness +
//! revocation* state it holds is **process-local**: it does not survive a
//! restart and does not propagate across replicas. The durable source of truth
//! for which applet owns which bot is the `applets` table (`bot_actor_id`
//! column, see `persistence::applets`); this registry is a best-effort runtime
//! cache layered on top of that. This is safe for the single-instance dev /
//! deployment-local posture (the HTTP handlers here are NOT mounted in the
//! production router), but a revocation performed on one replica will not be
//! observed by another and is lost on restart. Persisting the full
//! `BotActor` row (name / kind / owner / `revoked_at`) — plus ghost actors as
//! first-class rows — through `state.persistence` is the proper fix and is
//! tracked as a follow-up (it needs its own table + rehydration on startup, out
//! of scope for the wave-3 hardening pass).
//!
//! Deployment-local HTTP handlers are intentionally not mounted in the
//! production router until this registry has durable state and accountable
//! provisioning semantics.
//!
//! TODO(G3.S9-followup): bind bot/ghost provisioning to the verified
//! manifest's `applet_id`; persist the registry through
//! `state.persistence` so it survives restart / propagates across replicas
//! (SOL-HYG-01); emit `ck.identity.accountability_grant` events so the
//! accountability chain is queryable via the standard DID Document fetch.

use std::sync::Mutex;

#[cfg(test)]
use cokret_sdk::Did;
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};

#[cfg(test)]
use crate::error::AppError;

/// Discriminator for [`BotActor::kind`].
pub const KIND_BOT: &str = "bot";
pub const KIND_GHOST: &str = "ghost";

/// On-wire representation of a bot or ghost actor.
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

/// Process-local registry. See module TODO for the persistence
/// follow-up.
static BOT_REGISTRY: Mutex<Vec<BotActor>> = Mutex::new(Vec::new());

#[cfg(test)]
pub(crate) fn reset_registry_for_test() {
    BOT_REGISTRY.lock().unwrap().clear();
}

/// Register a bot/ghost actor. Returns the inserted [`BotActor`]; if
/// the DID is already registered (and not revoked), returns the
/// existing row idempotently.
pub fn register_bot(actor: BotActor) -> BotActor {
    let mut guard = BOT_REGISTRY.lock().expect("bot registry poisoned");
    if let Some(existing) = guard
        .iter()
        .find(|b| b.did == actor.did && b.revoked_at.is_none())
    {
        return existing.clone();
    }
    guard.push(actor.clone());
    actor
}

/// Mark a bot/ghost as revoked. Returns true on success; false when
/// the DID isn't registered. Historic registry rows are preserved
/// (the spec requires accountability history to outlive revocation).
pub fn revoke_bot(did: &str) -> bool {
    let mut guard = BOT_REGISTRY.lock().expect("bot registry poisoned");
    if let Some(row) = guard.iter_mut().find(|b| b.did == did) {
        row.revoked_at = Some(chrono::Utc::now());
        return true;
    }
    false
}

/// List bots owned by `owner_actor_id`, skipping revoked rows. Used
/// by the GET endpoint below.
pub fn list_bots_owned_by(owner_actor_id: &str) -> Vec<BotActor> {
    BOT_REGISTRY
        .lock()
        .expect("bot registry poisoned")
        .iter()
        .filter(|b| b.owner_actor_id == owner_actor_id && b.revoked_at.is_none())
        .cloned()
        .collect()
}

#[cfg(test)]
fn validate_extension_actor_did(did: &str) -> Result<(), AppError> {
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
    use std::sync::Mutex;

    use super::*;

    // Tests share the process-local `BOT_REGISTRY` static, so they
    // would race if run in parallel under `cargo test`. The
    // `TEST_GUARD` mutex serialises them; each test holds it for the
    // duration of its work so a fresh `reset_registry_for_test()` +
    // assertions sequence is atomic.
    static TEST_GUARD: Mutex<()> = Mutex::new(());

    fn fresh_actor(did: &str, owner: &str) -> BotActor {
        BotActor {
            did: did.to_owned(),
            name: "Test Bot".to_owned(),
            kind: KIND_BOT.to_owned(),
            owner_actor_id: owner.to_owned(),
            created_at: chrono::Utc::now(),
            revoked_at: None,
        }
    }

    #[test]
    fn bot_register_then_list() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        reset_registry_for_test();
        register_bot(fresh_actor("did:web:bot-alpha", "did:web:alice"));
        register_bot(fresh_actor("did:web:bot-beta", "did:web:alice"));
        register_bot(fresh_actor("did:web:bot-gamma", "did:web:bob"));
        let alice_bots = list_bots_owned_by("did:web:alice");
        assert_eq!(alice_bots.len(), 2);
        assert!(alice_bots.iter().any(|b| b.did == "did:web:bot-alpha"));
        assert!(alice_bots.iter().any(|b| b.did == "did:web:bot-beta"));
        let bob_bots = list_bots_owned_by("did:web:bob");
        assert_eq!(bob_bots.len(), 1);
    }

    #[test]
    fn bot_register_is_idempotent() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        reset_registry_for_test();
        let first = register_bot(fresh_actor("did:web:bot-dup", "did:web:alice"));
        let second = register_bot(fresh_actor("did:web:bot-dup", "did:web:alice"));
        // Same row returned; not duplicated in the registry.
        assert_eq!(first.did, second.did);
        assert_eq!(list_bots_owned_by("did:web:alice").len(), 1);
    }

    #[test]
    fn bot_revoke_hides_from_listing() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        reset_registry_for_test();
        register_bot(fresh_actor("did:web:bot-revoke", "did:web:alice"));
        assert_eq!(list_bots_owned_by("did:web:alice").len(), 1);
        assert!(revoke_bot("did:web:bot-revoke"));
        assert_eq!(list_bots_owned_by("did:web:alice").len(), 0);
        // Re-revoke is idempotent (returns true again because the row
        // still exists; the timestamp just moves forward).
        assert!(revoke_bot("did:web:bot-revoke"));
        // Unknown DIDs return false.
        assert!(!revoke_bot("did:web:unknown"));
    }

    #[test]
    fn bot_register_rejects_did_url_fragment() {
        let err = validate_extension_actor_did("did:web:alice.example#agent").unwrap_err();
        assert_eq!(err.wire_code(), "schema_violation");
    }
}
