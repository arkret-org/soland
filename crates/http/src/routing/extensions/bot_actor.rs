//! G3.S9 — Bot / ghost actor DID admission.
//!
//! Bot and ghost actors are second-class identities tied to a primary actor's
//! authority (the applet controller). Canonical provisioning happens through
//! `ak.self.applet.command.install` / `ak.applet.registration`; the durable
//! source of truth is the `applet_registrations` table (`persistence::applets`,
//! materialised as `AppletRecord`). Per
//! `extensions/applet-integration.md` §3–§5:
//!
//! - A **bot actor** is a stable per-applet DID. Created when the applet install completes
//!   (`applet_registrations.bot_actor_id`); lives until the applet is revoked
//!   (`applet_registrations.revoked_at`).
//! - A **ghost actor** is a per-external-user DID minted by the applet to represent an external
//!   user inside the portal realm. Recorded as a row in the applet record's `ghosts` array.
//!
//! Reads of that state go straight to the applet records; this module only owns
//! the DID admission rule applied on the write paths.
//!
//! TODO(G3.S9-followup): bind bot/ghost provisioning to the verified manifest's
//! `applet_id`; emit `ak.identity.accountability_grant` events so the
//! accountability chain is queryable via the standard DID Document fetch (the
//! ghost provisioning path already builds these via
//! `applet_bridge::build_ghost_accountability_grant_event`; bot-actor inception
//! grants remain a follow-up).

use arkret_identifiers::{DidCoreId, DidFullId};
use soland_http::error::AppError;

/// Validate that an extension actor DID is a bare DID scalar (no DID URL
/// fragment) and well-formed, before it is recorded against an applet.
/// Wired into the bot register / install-commit and ghost provision write
/// paths (G3.S9).
pub(super) fn validate_extension_actor_did(did: &str) -> Result<(), AppError> {
    if did.contains('#') {
        return Err(AppError::param_invalid(
            "bot and ghost actor DID must be a DID scalar without fragment",
        )
        .with_wire_code("schema_violation"));
    }
    if DidCoreId::new(did.to_owned()).is_ok() || DidFullId::new(did.to_owned()).is_ok() {
        return Ok(());
    }
    Err(
        AppError::param_invalid("bot or ghost actor identity is neither a Core DID nor a Full DID")
            .with_wire_code("schema_violation"),
    )
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

    #[test]
    fn bot_core_did_is_accepted() {
        validate_extension_actor_did("ak:did_core:web:alice.example")
            .expect("Core DID actor identity is valid");
    }
}
