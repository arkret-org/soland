//! G3.S9 — Bot / ghost actor registry (runnable stub).
//!
//! Bot and ghost actors are second-class identities tied to a primary
//! actor's authority (the applet controller). Per
//! `extensions/applet-integration.md` §3–§5:
//!
//! - A **bot actor** is a stable per-applet DID. Registered once when the applet completes manifest
//!   verification; lives until revoked.
//! - A **ghost actor** is a per-external-user DID minted by the applet to represent an external
//!   user inside the portal realm. Same wire shape as bots; the `kind` discriminator differs.
//!
//! Both flavours are recorded in a process-local registry
//! (`BOT_REGISTRY` below) for the stub. Persistence in the
//! `state.persistence` store is a follow-up — see TODO at module
//! bottom.
//!
//! HTTP surface (mounted under `/api/v1/extensions/bots`):
//!   POST   /api/v1/extensions/bots         — register a bot/ghost
//!   DELETE /api/v1/extensions/bots/{did}   — revoke a bot/ghost
//!   GET    /api/v1/extensions/bots         — list bots owned by caller
//!
//! Reducer dispatch hooks are exposed via
//! `apply_bot_register` / `apply_bot_revoke` so the central reducer
//! registry can fan out `cx.extensions.bot_actor.{register,revoke}`
//! event kinds through the same code path that the HTTP routes drive.
//!
//! TODO(G3.S9-followup): bind bot/ghost provisioning to the verified
//! manifest's `applet_id`; persist the registry through
//! `state.persistence` so it survives restart; emit
//! `cx.identity.accountability_grant` events so the accountability
//! chain is queryable via the standard DID Document fetch.

use std::sync::Mutex;

use contrix_sdk::Operation;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::error::AppError;
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;

/// Discriminator for [`BotActor::kind`].
pub const KIND_BOT: &str = "bot";
pub const KIND_GHOST: &str = "ghost";

/// On-wire representation of a bot or ghost actor.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BotActor {
    pub did: String,
    pub name: String,
    /// `"bot"` or `"ghost"`. We don't lean on an enum here so the wire
    /// stays open to future kinds without a breaking change in the JSON
    /// schema.
    pub kind: String,
    pub owner_actor_did: String,
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

/// List bots owned by `owner_actor_did`, skipping revoked rows. Used
/// by the GET endpoint below.
pub fn list_bots_owned_by(owner_actor_did: &str) -> Vec<BotActor> {
    BOT_REGISTRY
        .lock()
        .expect("bot registry poisoned")
        .iter()
        .filter(|b| b.owner_actor_did == owner_actor_did && b.revoked_at.is_none())
        .cloned()
        .collect()
}

// ── Reducer dispatch hooks ──────────────────────────────────────────

/// Reducer adapter for `cx.extensions.bot_actor.register`.
///
/// The full reducer signature returns `ProjectionEffect`, but we keep
/// this helper standalone (rather than going through `ProjectionState`)
/// because the bot/ghost registry is module-local stub state. The
/// adapter in `reducer.rs` calls into here and discards the result
/// alongside `ProjectionEffect::Ignored`.
pub fn apply_bot_register(op: &Operation) -> Option<BotActor> {
    let payload = op.payload.as_object()?;
    let did = payload.get("did").and_then(Value::as_str)?.to_owned();
    let name = payload
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let kind = payload
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or(KIND_BOT)
        .to_owned();
    let owner = payload
        .get("owner_actor_did")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let actor = BotActor {
        did,
        name,
        kind,
        owner_actor_did: owner,
        created_at: op.created_at,
        revoked_at: None,
    };
    Some(register_bot(actor))
}

/// Reducer adapter for `cx.extensions.bot_actor.revoke`.
pub fn apply_bot_revoke(op: &Operation) -> bool {
    op.payload
        .get("did")
        .and_then(Value::as_str)
        .map(revoke_bot)
        .unwrap_or(false)
}

// ── HTTP surface ────────────────────────────────────────────────────

pub(super) fn router() -> Router {
    Router::with_path("bots")
        .post(register_endpoint)
        .get(list_endpoint)
        .push(Router::with_path("{did}").delete(revoke_endpoint))
}

#[endpoint(
    operation_id = "cx.extension.soland.extensions.bots.register",
    tags("extensions"),
    summary = "Register a bot or ghost actor"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.extensions.bots.register"))]
async fn register_endpoint(
    aa: AuthArgs,
    body: JsonBody<Value>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let did = body
        .get("did")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::invalid_param("did is required"))?
        .to_owned();
    let name = body
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let kind = body
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or(KIND_BOT)
        .to_owned();
    if !(kind == KIND_BOT || kind == KIND_GHOST) {
        return Err(AppError::invalid_param(
            "kind MUST be either \"bot\" or \"ghost\"",
        ));
    }
    let actor = register_bot(BotActor {
        did,
        name,
        kind,
        owner_actor_did: session.actor.clone(),
        created_at: chrono::Utc::now(),
        revoked_at: None,
    });
    json_ok(serde_json::to_value(actor).expect("bot actor serializes"))
}

#[endpoint(
    operation_id = "cx.extension.soland.extensions.bots.list",
    tags("extensions"),
    summary = "List bots / ghost actors owned by the authenticated actor"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.extensions.bots.list"))]
async fn list_endpoint(aa: AuthArgs, depot: &mut Depot, req: &mut Request) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let bots = list_bots_owned_by(&session.actor);
    json_ok(json!({ "bots": bots }))
}

#[endpoint(
    operation_id = "cx.extension.soland.extensions.bots.revoke",
    tags("extensions"),
    summary = "Revoke a bot / ghost actor"
)]
#[tracing::instrument(skip_all, fields(op = "cx.extension.soland.extensions.bots.revoke"))]
async fn revoke_endpoint(aa: AuthArgs, depot: &mut Depot, req: &mut Request) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let did = req
        .param::<String>("did")
        .ok_or_else(|| AppError::missing_param("did path segment required"))?;
    let revoked = revoke_bot(&did);
    json_ok(json!({
        "did": did,
        "revoked": revoked,
        "revoked_at": chrono::Utc::now(),
    }))
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
            owner_actor_did: owner.to_owned(),
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
}
