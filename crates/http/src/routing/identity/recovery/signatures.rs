use super::*;

pub(super) fn authorization_event_actor_matches_account(
    actor_key: &str,
    account_id: &AccountId,
) -> bool {
    arkret_wire::ActorId::account(account_id.clone())
        .canonical_key()
        .is_ok_and(|expected| expected == actor_key)
}

#[cfg(test)]
mod account_lineage_tests {
    use super::*;

    #[test]
    fn device_authorization_requires_the_complete_account_actor() {
        let principal = arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let station = arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let account = AccountId::new(principal.clone(), station);
        let expected = arkret_wire::ActorId::account(account.clone());
        assert!(authorization_event_actor_matches_account(
            &expected.canonical_key().unwrap(),
            &account,
        ));
        let foreign = arkret_wire::ActorId::account(AccountId::new(
            principal.clone(),
            arkret_wire::DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
        ));
        for key in [
            foreign.canonical_key().unwrap(),
            arkret_wire::ActorId::service(principal.clone())
                .canonical_key()
                .unwrap(),
            principal.to_string(),
        ] {
            assert!(!authorization_event_actor_matches_account(&key, &account));
        }
    }
}
