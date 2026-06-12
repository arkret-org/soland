//! Server-side wrapper around the shared v1 push rule core.
//!
//! Soland adds dispatch-oriented fields (`deliver`, `blind_wakeup`, and
//! diagnostic-only `internal_reason`) on top of the SDK's protocol-level
//! watch-state decision.

pub use cokret_sdk::push_rule_core::{EventContext, WatchLevel, reason_code};
use cokret_sdk::push_rule_core::{ShouldNotify as CoreShouldNotify, evaluate_watch_level};

/// Internal diagnostic strings. These are deliberately *not* a stable wire
/// contract: they exist for soland logs, metrics, and audit rows only.
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
/// `deliver` answers "should the push gateway be called at all?" Blind
/// wakeups still set `deliver=true` because they consume a gateway slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PushDecision {
    pub deliver: bool,
    /// True when delivery should be a body-free blind wakeup.
    pub blind_wakeup: bool,
    /// Wire-safe reason code. Safe to forward to floria / UI hints.
    pub reason_code: String,
    /// Diagnostic-only reason. Never forwarded across a vendor gateway
    /// boundary.
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

/// Server-side core evaluator. Delegates the protocol decision to the SDK and
/// projects it into soland's richer dispatch shape.
pub fn evaluate_push_rule(receiver: WatchLevel, event: &EventContext) -> PushDecision {
    let (decision, reason) = evaluate_watch_level(receiver, event);
    match decision {
        CoreShouldNotify::BlindWakeup => PushDecision::blind_wakeup(),
        CoreShouldNotify::Notify => PushDecision::notify(reason, notify_internal_reason(receiver)),
        CoreShouldNotify::DontNotify => {
            PushDecision::dont_notify(reason, suppress_internal_reason(reason))
        }
    }
}

fn notify_internal_reason(receiver: WatchLevel) -> &'static str {
    match receiver {
        WatchLevel::Muted => unreachable!("muted cannot notify"),
        WatchLevel::All => internal_reason::WATCH_LEVEL_ALL,
        WatchLevel::MentionsOnly => internal_reason::WATCH_LEVEL_MENTIONS_ONLY_DELIVER,
        WatchLevel::Participating => internal_reason::WATCH_LEVEL_PARTICIPATING_DELIVER,
    }
}

fn suppress_internal_reason(reason: &'static str) -> &'static str {
    if reason == reason_code::MUTED {
        internal_reason::MUTED_SHORT_CIRCUIT
    } else if reason == reason_code::NOT_MENTIONED {
        internal_reason::MENTIONS_ONLY_FILTERED
    } else if reason == reason_code::NOT_PARTICIPATING {
        internal_reason::PARTICIPATING_FILTERED
    } else {
        reason
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
        assert!(WatchLevel::from_wire("none").is_none());
    }

    #[test]
    fn muted_short_circuit() {
        let mut c = ctx();
        c.mentions_actor = true;

        let decision = evaluate_push_rule(WatchLevel::Muted, &c);

        assert!(!decision.deliver);
        assert!(!decision.blind_wakeup);
        assert_eq!(decision.reason_code, reason_code::MUTED);
        assert_eq!(
            decision.internal_reason,
            internal_reason::MUTED_SHORT_CIRCUIT
        );
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
        c.assigned_to_actor = true;
        let decision = evaluate_push_rule(WatchLevel::MentionsOnly, &c);
        assert!(decision.deliver);
        assert!(!decision.blind_wakeup);
        assert_eq!(decision.reason_code, reason_code::WATCH_ALLOWS);
        assert_eq!(
            decision.internal_reason,
            internal_reason::WATCH_LEVEL_MENTIONS_ONLY_DELIVER
        );
    }

    #[test]
    fn participating_filters_non_participants() {
        let decision = evaluate_push_rule(WatchLevel::Participating, &ctx());

        assert!(!decision.deliver);
        assert_eq!(decision.reason_code, reason_code::NOT_PARTICIPATING);
        assert_eq!(
            decision.internal_reason,
            internal_reason::PARTICIPATING_FILTERED
        );

        let mut c = ctx();
        c.participating_thread_update = true;
        let decision = evaluate_push_rule(WatchLevel::Participating, &c);
        assert!(decision.deliver);
        assert_eq!(decision.reason_code, reason_code::WATCH_ALLOWS);
        assert_eq!(
            decision.internal_reason,
            internal_reason::WATCH_LEVEL_PARTICIPATING_DELIVER
        );
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
        for level in [
            WatchLevel::MentionsOnly,
            WatchLevel::Participating,
            WatchLevel::All,
        ] {
            let mut c = ctx();
            c.is_e2ee = true;

            let decision = evaluate_push_rule(level, &c);

            assert!(decision.deliver);
            assert!(decision.blind_wakeup);
            assert_eq!(decision.reason_code, reason_code::BLIND_WAKEUP_REQUIRED);
            assert_eq!(decision.internal_reason, internal_reason::E2EE_BLIND_WAKEUP);
        }

        let mut c = ctx();
        c.is_e2ee = true;
        let decision = evaluate_push_rule(WatchLevel::Muted, &c);
        assert!(!decision.deliver);
        assert!(!decision.blind_wakeup);
        assert_eq!(decision.reason_code, reason_code::MUTED);
    }

    #[test]
    fn internal_reason_never_uses_public_reason_code() {
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
}
