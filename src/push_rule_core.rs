//! T4.4 — Push rule core v1 (server-side).
//!
//! Server-side counterpart to `chime::push_rule_core`. The wire-level
//! semantics intentionally match the client helper byte-for-byte so a
//! receiver evaluating the same `(watch_level, event)` pair offline
//! converges on the same decision the Sync Service would have made.
//!
//! ## Evaluation order
//!
//! 1. Resolve the receiver's effective watch level (`muted` |
//!    `mentions_only` | `participating` | `all`).
//! 2. `muted` short-circuits to `dont_notify` (pre-engine deny rule).
//! 3. Watch-level vs event:
//!    - `mentions_only` + the message does not mention the receiver →
//!      don't notify.
//!    - `participating` + the receiver hasn't operated in any cell of
//!      the surrounding flow → don't notify.
//!    - `all` → notify.
//!    - `muted` → never notify (handled at step 2).
//!
//! Push rules only decide the *delivery shape* (blind wakeup vs
//! visible). Whether the receiver has any access to the Space at all
//! is decided by the Space ACL, not here.
//!
//! ## Public vs internal reasons
//!
//! Decisions carry both a wire-safe `reason_code` (suitable for
//! floria `RejectedDevice.reason` / yougen UI hints) and an
//! `internal_reason` (e.g. `muted_short_circuit`) that stays inside
//! soland's logs/metrics so vendor push gateways never see the
//! receiver's mute state.

use serde::{Deserialize, Serialize};

/// Receiver's effective watch level for the scope being notified.
/// Wire encoding matches `cx.flow.watch.set`'s `level` field.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchLevel {
    /// Pre-engine deny rule. Never deliver, even for direct mentions.
    Muted,
    /// Only deliver when the receiver is explicitly mentioned /
    /// assigned.
    #[default]
    MentionsOnly,
    /// Deliver when the receiver has participated in the surrounding
    /// flow / thread.
    Participating,
    /// Deliver every event in the watched scope.
    All,
}

impl WatchLevel {
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "muted" => Some(Self::Muted),
            "mentions_only" => Some(Self::MentionsOnly),
            "participating" => Some(Self::Participating),
            "all" => Some(Self::All),
            _ => None,
        }
    }

    pub fn as_wire(self) -> &'static str {
        match self {
            Self::Muted => "muted",
            Self::MentionsOnly => "mentions_only",
            Self::Participating => "participating",
            Self::All => "all",
        }
    }
}

/// Minimal event metadata required to make a v1-core decision.
///
/// The fields intentionally mirror `chime::PushRuleEventContext` so a
/// soland decision and a chime-side decision agree byte-for-byte
/// (cross-project consistency vectors in cotest exercise this).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EventContext {
    /// Whether the event explicitly mentions the receiver.
    pub mentions_actor: bool,
    /// Whether the event is addressed/assigned to the receiver.
    pub assigned_to_actor: bool,
    /// Whether this event replies to a thread the receiver authored.
    pub reply_to_self: bool,
    /// Whether the receiver has already participated in the
    /// surrounding flow / thread (operated in any cell).
    pub participating_thread_update: bool,
    /// E2EE event flag. When set together with `local_decrypted=false`
    /// the decision becomes "blind wakeup" so the client can
    /// re-evaluate after decryption.
    pub is_e2ee: bool,
    /// Whether the dispatcher already knows the event was decrypted
    /// (always `false` on the server path; reserved for completeness
    /// so the same `EventContext` works for client-side re-evaluation).
    pub local_decrypted: bool,
}

impl EventContext {
    /// `mentions_only` directs delivery on direct addressing.
    pub fn directed(&self) -> bool {
        self.mentions_actor || self.assigned_to_actor
    }

    /// `participating` directs delivery on any form of receiver
    /// involvement with the surrounding flow.
    pub fn participated(&self) -> bool {
        self.directed() || self.reply_to_self || self.participating_thread_update
    }
}

/// Stable wire reason codes returned by [`evaluate_push_rule`]. These
/// are safe to surface in `RejectedDevice.reason` and UI hints — they
/// describe *why the receiver does/doesn't get the message* without
/// leaking diagnostic state (which is reported via `internal_reason`).
pub mod reason_code {
    pub const MUTED: &str = "muted";
    pub const NOT_MENTIONED: &str = "not_mentioned";
    pub const NOT_PARTICIPATING: &str = "not_participating";
    pub const WATCH_ALLOWS: &str = "watch_allows";
    pub const BLIND_WAKEUP_REQUIRED: &str = "blind_wakeup_required";
}

/// Internal diagnostic strings. These are deliberately *not* a stable
/// wire contract — they exist for soland logs / metrics / audit rows
/// only. Vendor push gateways must never see these (only `reason_code`).
pub mod internal_reason {
    pub const MUTED_SHORT_CIRCUIT: &str = "muted_short_circuit";
    pub const MENTIONS_ONLY_FILTERED: &str = "mentions_only_filtered";
    pub const PARTICIPATING_FILTERED: &str = "participating_filtered";
    pub const WATCH_LEVEL_ALL: &str = "watch_level_all";
    pub const WATCH_LEVEL_MENTIONS_ONLY_DELIVER: &str = "watch_level_mentions_only_deliver";
    pub const WATCH_LEVEL_PARTICIPATING_DELIVER: &str = "watch_level_participating_deliver";
    pub const E2EE_BLIND_WAKEUP: &str = "e2ee_blind_wakeup";
}

/// Outcome of evaluating the v1 core rules against `(receiver, event)`.
///
/// `deliver` answers "should the push gateway be called at all?" —
/// blind wakeups still set `deliver=true` because they consume a
/// gateway slot. `reason_code` is the wire-safe code; `internal_reason`
/// is the diagnostic detail that must stay inside soland.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PushDecision {
    pub deliver: bool,
    /// True when delivery should be a body-free blind wakeup (E2EE
    /// path). Always implies `deliver=true`.
    pub blind_wakeup: bool,
    /// Wire-safe reason code. Forwarded to floria via
    /// `RejectedDevice.reason` for non-deliveries, and used by yougen
    /// for UI hint strings.
    pub reason_code: String,
    /// Diagnostic-only reason. Never forwarded across a vendor gateway
    /// boundary. Safe to log + metric.
    pub internal_reason: String,
}

impl PushDecision {
    pub fn dont_notify(reason_code: &'static str, internal_reason: &'static str) -> Self {
        Self {
            deliver: false,
            blind_wakeup: false,
            reason_code: reason_code.to_owned(),
            internal_reason: internal_reason.to_owned(),
        }
    }

    pub fn notify(reason_code: &'static str, internal_reason: &'static str) -> Self {
        Self {
            deliver: true,
            blind_wakeup: false,
            reason_code: reason_code.to_owned(),
            internal_reason: internal_reason.to_owned(),
        }
    }

    pub fn blind_wakeup() -> Self {
        Self {
            deliver: true,
            blind_wakeup: true,
            reason_code: reason_code::BLIND_WAKEUP_REQUIRED.to_owned(),
            internal_reason: internal_reason::E2EE_BLIND_WAKEUP.to_owned(),
        }
    }
}

/// Server-side core evaluator. Mirrors `chime::evaluate_watch_level`'s
/// decision but returns a richer [`PushDecision`] for the dispatch
/// pipeline.
///
/// `receiver` is the watch level resolved from
/// `projection_flow_watches` (or the receiver's effective default if
/// no per-flow watch is set). `event` is the minimal metadata needed
/// to make a v1-core call.
pub fn evaluate_push_rule(receiver: WatchLevel, event: &EventContext) -> PushDecision {
    // Pre-engine deny rule — never reach the engine if muted.
    if matches!(receiver, WatchLevel::Muted) {
        return PushDecision::dont_notify(reason_code::MUTED, internal_reason::MUTED_SHORT_CIRCUIT);
    }

    // E2EE blind wakeup: we cannot evaluate the full payload
    // server-side; the receiver client must decrypt and re-run the
    // same logic via chime::evaluate_watch_level.
    if event.is_e2ee && !event.local_decrypted {
        return PushDecision::blind_wakeup();
    }

    match receiver {
        WatchLevel::Muted => unreachable!("handled above"),
        WatchLevel::All => {
            PushDecision::notify(reason_code::WATCH_ALLOWS, internal_reason::WATCH_LEVEL_ALL)
        }
        WatchLevel::MentionsOnly => {
            if event.directed() {
                PushDecision::notify(
                    reason_code::WATCH_ALLOWS,
                    internal_reason::WATCH_LEVEL_MENTIONS_ONLY_DELIVER,
                )
            } else {
                PushDecision::dont_notify(
                    reason_code::NOT_MENTIONED,
                    internal_reason::MENTIONS_ONLY_FILTERED,
                )
            }
        }
        WatchLevel::Participating => {
            if event.participated() {
                PushDecision::notify(
                    reason_code::WATCH_ALLOWS,
                    internal_reason::WATCH_LEVEL_PARTICIPATING_DELIVER,
                )
            } else {
                PushDecision::dont_notify(
                    reason_code::NOT_PARTICIPATING,
                    internal_reason::PARTICIPATING_FILTERED,
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> EventContext {
        EventContext::default()
    }

    #[test]
    fn watch_level_wire_roundtrip() {
        for level in [
            WatchLevel::Muted,
            WatchLevel::MentionsOnly,
            WatchLevel::Participating,
            WatchLevel::All,
        ] {
            assert_eq!(WatchLevel::from_wire(level.as_wire()), Some(level));
        }
        assert!(WatchLevel::from_wire("nope").is_none());
    }

    #[test]
    fn muted_short_circuit() {
        let decision = evaluate_push_rule(WatchLevel::Muted, &ctx());
        assert!(!decision.deliver);
        assert!(!decision.blind_wakeup);
        assert_eq!(decision.reason_code, reason_code::MUTED);
        assert_eq!(
            decision.internal_reason,
            internal_reason::MUTED_SHORT_CIRCUIT
        );

        // Even mentions are suppressed.
        let mut c = ctx();
        c.mentions_actor = true;
        let decision = evaluate_push_rule(WatchLevel::Muted, &c);
        assert!(!decision.deliver);
        assert_eq!(decision.reason_code, reason_code::MUTED);
    }

    #[test]
    fn mentions_only_filters_non_mentions() {
        let decision = evaluate_push_rule(WatchLevel::MentionsOnly, &ctx());
        assert!(!decision.deliver);
        assert_eq!(decision.reason_code, reason_code::NOT_MENTIONED);
        assert_eq!(
            decision.internal_reason,
            internal_reason::MENTIONS_ONLY_FILTERED
        );

        let mut c = ctx();
        c.mentions_actor = true;
        let decision = evaluate_push_rule(WatchLevel::MentionsOnly, &c);
        assert!(decision.deliver);
        assert!(!decision.blind_wakeup);
        assert_eq!(decision.reason_code, reason_code::WATCH_ALLOWS);

        let mut c = ctx();
        c.assigned_to_actor = true;
        let decision = evaluate_push_rule(WatchLevel::MentionsOnly, &c);
        assert!(decision.deliver);
        assert!(!decision.blind_wakeup);
        assert_eq!(decision.reason_code, reason_code::WATCH_ALLOWS);
    }

    #[test]
    fn participating_filters_non_participants() {
        let decision = evaluate_push_rule(WatchLevel::Participating, &ctx());
        assert!(!decision.deliver);
        assert_eq!(decision.reason_code, reason_code::NOT_PARTICIPATING);

        let mut c = ctx();
        c.participating_thread_update = true;
        let decision = evaluate_push_rule(WatchLevel::Participating, &c);
        assert!(decision.deliver);
        assert_eq!(decision.reason_code, reason_code::WATCH_ALLOWS);

        let mut c = ctx();
        c.reply_to_self = true;
        let decision = evaluate_push_rule(WatchLevel::Participating, &c);
        assert!(decision.deliver);

        let mut c = ctx();
        c.mentions_actor = true; // mentions imply participation too
        let decision = evaluate_push_rule(WatchLevel::Participating, &c);
        assert!(decision.deliver);
    }

    #[test]
    fn all_passes_all() {
        let decision = evaluate_push_rule(WatchLevel::All, &ctx());
        assert!(decision.deliver);
        assert!(!decision.blind_wakeup);
        assert_eq!(decision.reason_code, reason_code::WATCH_ALLOWS);
        assert_eq!(decision.internal_reason, internal_reason::WATCH_LEVEL_ALL);
    }

    #[test]
    fn e2ee_blind_wakeup_required() {
        let mut c = ctx();
        c.is_e2ee = true;
        let decision = evaluate_push_rule(WatchLevel::MentionsOnly, &c);
        assert!(decision.deliver);
        assert!(decision.blind_wakeup);
        assert_eq!(decision.reason_code, reason_code::BLIND_WAKEUP_REQUIRED);
        assert_eq!(decision.internal_reason, internal_reason::E2EE_BLIND_WAKEUP);

        // Muted still short-circuits ahead of blind wakeup — never
        // burn a wakeup slot on a muted flow.
        let mut c = ctx();
        c.is_e2ee = true;
        let decision = evaluate_push_rule(WatchLevel::Muted, &c);
        assert!(!decision.deliver);
        assert!(!decision.blind_wakeup);
        assert_eq!(decision.reason_code, reason_code::MUTED);
    }

    #[test]
    fn internal_reason_never_uses_public_reason_code() {
        // Catch accidental reuse of public reason strings in the
        // internal channel — vendor gateways must not see internal
        // strings, but if a developer copy-pastes from `reason_code`
        // into `internal_reason` we still want them to be different
        // identifiers so logs/audit/wire stay distinguishable.
        for r in [
            internal_reason::MUTED_SHORT_CIRCUIT,
            internal_reason::MENTIONS_ONLY_FILTERED,
            internal_reason::PARTICIPATING_FILTERED,
            internal_reason::WATCH_LEVEL_ALL,
            internal_reason::WATCH_LEVEL_MENTIONS_ONLY_DELIVER,
            internal_reason::WATCH_LEVEL_PARTICIPATING_DELIVER,
            internal_reason::E2EE_BLIND_WAKEUP,
        ] {
            assert_ne!(r, reason_code::MUTED);
            assert_ne!(r, reason_code::NOT_MENTIONED);
            assert_ne!(r, reason_code::NOT_PARTICIPATING);
            assert_ne!(r, reason_code::WATCH_ALLOWS);
            assert_ne!(r, reason_code::BLIND_WAKEUP_REQUIRED);
        }
    }

    // T4.4 cross-project coverage lives in cotest:
    // `tests/push_rule_core_consistency.rs` imports this module plus
    // chime and yougen, then drives the shared vector fixture at
    // `tests/fixtures/push_rule_core_vectors.json`.
}
