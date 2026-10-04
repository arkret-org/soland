use super::*;

fn managed_actor_installation_selects_event(
    installation_scope: &arkret_wire::ScopeRef,
    installation_realm_id: &str,
    event_scope: Option<&arkret_wire::ScopeRef>,
    event_realm_id: &str,
    is_pcr_rotation: bool,
    actor_pcr_realm_id: &str,
) -> bool {
    if is_pcr_rotation {
        event_realm_id == actor_pcr_realm_id
    } else {
        event_scope == Some(installation_scope) && event_realm_id == installation_realm_id
    }
}

#[allow(
    clippy::items_after_test_module,
    reason = "the focused regression tests stay adjacent to their private scope-selection helper"
)]
mod managed_actor_scope_selection_tests {
    use super::managed_actor_installation_selects_event;

    #[test]
    fn non_pcr_write_selects_exact_scope_before_liveness() {
        let realm_id = arkret_wire::RealmId::new(
            "ak:realm:AXTOWXiR0H0NRFksL2Dt7uYvlaNckYIqkzsoMPPxW5MH".to_owned(),
        )
        .unwrap();
        let realm = arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        };
        let circle = arkret_wire::ScopeRef::Circle {
            realm_id: realm_id.clone(),
            circle_id: arkret_wire::CircleId::new(
                "ak:circle:AXTOWXiR0H0NRFksL2Dt7uYvlaNckYIqkzsoMPPxW5MH".to_owned(),
            )
            .unwrap(),
        };
        assert!(!managed_actor_installation_selects_event(
            &realm,
            realm_id.as_str(),
            Some(&circle),
            realm_id.as_str(),
            false,
            "ak:realm:pcr"
        ));
        assert!(managed_actor_installation_selects_event(
            &circle,
            realm_id.as_str(),
            Some(&circle),
            realm_id.as_str(),
            false,
            "ak:realm:pcr"
        ));
    }

    #[test]
    fn pcr_rotation_selects_any_scope_only_through_shared_pcr() {
        let realm_id = arkret_wire::RealmId::new(
            "ak:realm:AXTOWXiR0H0NRFksL2Dt7uYvlaNckYIqkzsoMPPxW5MH".to_owned(),
        )
        .unwrap();
        let scope = arkret_wire::ScopeRef::Realm { realm_id };
        assert!(managed_actor_installation_selects_event(
            &scope,
            "ak:realm:portal",
            None,
            "ak:realm:pcr",
            true,
            "ak:realm:pcr"
        ));
        assert!(!managed_actor_installation_selects_event(
            &scope,
            "ak:realm:portal",
            None,
            "ak:realm:other",
            true,
            "ak:realm:pcr"
        ));
    }
}
