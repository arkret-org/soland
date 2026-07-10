//! SPI-SOL-004 — hardened Realm mention-routing forced downgrade
//! (push-notifications.md §4.5).
//!
//! The canonical effective policy is computed by the SDK helper
//! [`arkret_sdk::effective_mention_routing_hint`]; this module is the single
//! gate every mention-routing sidecar token operation MUST pass through
//! BEFORE any register / compare / persist. For the three hardened profiles
//! (`ak.profile.mls.minimal_metadata_realm.v1`,
//! `ak.profile.attested_audit.e2ee.v1`, `ak.profile.disclosed_audit.e2ee.v1`)
//! and for any unknown / undeclared hint the effective policy is `disabled`:
//! mentions go over the blind / batch wakeup fallback and the sidecar surface
//! is never touched. Ordinary `ak.profile.e2ee_client.v1` Realms keep the
//! explicit opt-in positive path.
//!
//! The projected `mention_routing_hint` display field on messages
//! (`projection/timeline.rs`) is NOT a policy input — policy comes only from
//! the Realm's declared profiles + declared policy value through this gate.

use arkret_sdk::{MentionRoutingHint, effective_mention_routing_hint};

use crate::state::AppState;

/// The sidecar token surface a mention-routing implementation exposes. The
/// production wiring drives it only after [`drive_mention_routing_sidecar`]
/// resolves the effective hint; tests inject a counting fake to prove
/// hardened Realms never reach register / compare / persist.
pub(crate) trait MentionRoutingSidecarOps {
    /// Register a recipient's opaque routing token (opt-in flow only).
    fn register_token(&mut self, recipient: &str, token: &str);
    /// Compare a message sidecar tag against a registered token.
    fn compare_token(&mut self, sidecar_tag: &str) -> bool;
    /// Persist a sidecar token for later comparison.
    fn persist_token(&mut self, sidecar_tag: &str);
    /// Blind / batch wakeup fallback — the only permitted path when the
    /// effective hint is `disabled`.
    fn blind_or_batch_fallback(&mut self);
}

/// Resolve the effective mention-routing hint for a Realm from its projected
/// meta. Missing meta, missing declaration, or an unknown declared value all
/// fail closed to `disabled`.
pub(crate) async fn effective_realm_mention_routing_hint(
    state: &AppState,
    realm_id: &str,
    declared_hint: Option<&str>,
) -> MentionRoutingHint {
    let Some(record) = state
        .persistence
        .realm_meta()
        .get(realm_id)
        .await
        .ok()
        .flatten()
    else {
        return MentionRoutingHint::Disabled;
    };
    let mut profiles: Vec<String> = Vec::new();
    if let Some(profile) = record.encryption_profile.clone() {
        profiles.push(profile);
    }
    if record.minimal_metadata_realm {
        profiles.push(arkret_sdk::mls::MINIMAL_METADATA_REALM_PROFILE.to_owned());
    }
    effective_mention_routing_hint(&profiles, declared_hint)
}

/// The single decision point in front of the sidecar surface: compute the
/// effective hint, then route to exactly one side. `disabled` never touches
/// register / compare / persist; the opt-in side is only reachable for an
/// ordinary E2EE Realm with an explicit `recipient_registered_token`
/// declaration.
pub(crate) fn drive_mention_routing_sidecar<S: MentionRoutingSidecarOps + ?Sized>(
    realm_profiles: &[String],
    declared_hint: Option<&str>,
    message_sidecar_tags: &[String],
    sidecar: &mut S,
) -> MentionRoutingHint {
    let effective = effective_mention_routing_hint(realm_profiles, declared_hint);
    match effective {
        MentionRoutingHint::Disabled => sidecar.blind_or_batch_fallback(),
        MentionRoutingHint::RecipientRegisteredToken => {
            for tag in message_sidecar_tags {
                sidecar.persist_token(tag);
                let _ = sidecar.compare_token(tag);
            }
        }
    }
    effective
}

#[cfg(test)]
mod tests {
    use arkret_sdk::{HARDENED_MENTION_ROUTING_PROFILES, PROFILE_E2EE_CLIENT};

    use super::*;

    /// Observable fake proving which side of the gate ran.
    #[derive(Default)]
    struct CountingSidecar {
        register_calls: usize,
        compare_calls: usize,
        persist_calls: usize,
        fallback_calls: usize,
    }

    impl MentionRoutingSidecarOps for CountingSidecar {
        fn register_token(&mut self, _recipient: &str, _token: &str) {
            self.register_calls += 1;
        }
        fn compare_token(&mut self, _sidecar_tag: &str) -> bool {
            self.compare_calls += 1;
            false
        }
        fn persist_token(&mut self, _sidecar_tag: &str) {
            self.persist_calls += 1;
        }
        fn blind_or_batch_fallback(&mut self) {
            self.fallback_calls += 1;
        }
    }

    const SIDECAR_TAG: &str = "opaque-routing-tag";

    /// `ak.vector.push.mention_routing_hint_disabled_on_hardened_realm.v1` —
    /// each hardened profile forces `disabled` even against an explicit
    /// `recipient_registered_token` declaration, with register / compare /
    /// persist all provably 0 and exactly one blind/batch fallback.
    #[test]
    fn hardened_profiles_never_reach_the_sidecar_surface() {
        for hardened in HARDENED_MENTION_ROUTING_PROFILES {
            let mut sidecar = CountingSidecar::default();
            let effective = drive_mention_routing_sidecar(
                &[PROFILE_E2EE_CLIENT.to_owned(), (*hardened).to_owned()],
                Some("recipient_registered_token"),
                &[SIDECAR_TAG.to_owned()],
                &mut sidecar,
            );
            assert_eq!(effective, MentionRoutingHint::Disabled, "{hardened}");
            assert_eq!(sidecar.register_calls, 0, "{hardened}");
            assert_eq!(sidecar.compare_calls, 0, "{hardened}");
            assert_eq!(sidecar.persist_calls, 0, "{hardened}");
            assert_eq!(sidecar.fallback_calls, 1, "{hardened}");
        }
    }

    /// Unknown / undeclared hints fail closed to `disabled` regardless of
    /// profile mix.
    #[test]
    fn unknown_and_undeclared_hints_fail_closed() {
        for declared in [Some("push_all_metadata"), None] {
            let mut sidecar = CountingSidecar::default();
            let effective = drive_mention_routing_sidecar(
                &[PROFILE_E2EE_CLIENT.to_owned()],
                declared,
                &[SIDECAR_TAG.to_owned()],
                &mut sidecar,
            );
            assert_eq!(effective, MentionRoutingHint::Disabled);
            assert_eq!(
                (
                    sidecar.register_calls,
                    sidecar.compare_calls,
                    sidecar.persist_calls
                ),
                (0, 0, 0)
            );
            assert_eq!(sidecar.fallback_calls, 1);
        }
    }

    /// Positive control: an ordinary E2EE Realm with an explicit opt-in keeps
    /// the recipient-registered-token path (persist + compare run, fallback
    /// does not).
    #[test]
    fn ordinary_e2ee_opt_in_keeps_the_positive_path() {
        let mut sidecar = CountingSidecar::default();
        let effective = drive_mention_routing_sidecar(
            &[
                PROFILE_E2EE_CLIENT.to_owned(),
                "ak.profile.kanban_mvp.v1".to_owned(),
            ],
            Some("recipient_registered_token"),
            &[SIDECAR_TAG.to_owned()],
            &mut sidecar,
        );
        assert_eq!(effective, MentionRoutingHint::RecipientRegisteredToken);
        assert_eq!(sidecar.persist_calls, 1);
        assert_eq!(sidecar.compare_calls, 1);
        assert_eq!(sidecar.fallback_calls, 0);
    }
}
