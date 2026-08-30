use super::*;

pub(super) async fn preflight_mls_welcome_claim_signature_reject(
    state: &AppState,
    session: &SessionRecord,
    object: &serde_json::Map<String, Value>,
    actor_id: &str,
    operation: &Operation,
    internal_admission: Option<&InternalEventAdmission>,
) -> Option<String> {
    if kinds::canonical_kind(operation) != arkret_wire::EventKind::MlsWelcome {
        return None;
    }
    let welcome = match operation.typed_payload::<arkret_wire::event_spec::MlsWelcome>() {
        Ok(welcome) => welcome,
        Err(_) => {
            return Some(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH.to_owned());
        }
    };
    let envelope = &welcome.claim_envelope;
    if !welcome_requester_matches_actor(&envelope.requester_actor_id, actor_id) {
        return Some(arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH.to_owned());
    }
    let sender_device_id = welcome.sender_device_id.as_ref().map(|id| id.as_str());
    let producer_signing_key = internal_admission.and_then(|admission| {
        admission.federated_producer_signing_key(session, object, envelope.signature.kid.as_str())
    });
    crate::routing::identity::device_signing::verify_mls_welcome_claim_envelope_signature(
        state,
        envelope,
        &welcome.claim_receipt,
        sender_device_id,
        producer_signing_key,
    )
    .await
    .err()
    .map(str::to_owned)
}

pub(super) async fn preflight_mls_welcome_claim_ledger_reject(
    state: &AppState,
    actor_id: &str,
    operation: &Operation,
) -> Option<String> {
    if kinds::canonical_kind(operation) != arkret_wire::EventKind::MlsWelcome {
        return None;
    }
    crate::routing::mls::validate_local_welcome_peer_claim(
        state,
        operation.realm_id.as_str(),
        actor_id,
        &operation.payload,
    )
    .await
    .err()
    .map(|reason| {
        if reason == "peer_claim_welcome_pending" {
            "dependency_missing".to_owned()
        } else {
            arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH.to_owned()
        }
    })
}

fn welcome_requester_matches_actor(requester: &arkret_wire::ActorId, actor_id: &str) -> bool {
    serde_json::from_str::<arkret_wire::ActorId>(actor_id).is_ok_and(|actor| &actor == requester)
}

#[cfg(test)]
mod tests {
    use arkret_wire::{AccountId, ActorId, DidCoreId};

    use super::welcome_requester_matches_actor;

    #[test]
    fn welcome_requester_requires_the_complete_event_actor() {
        let principal = DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let station = DidCoreId::new("ak:did_core:web:station-a.example").unwrap();
        let account = ActorId::account(AccountId::new(principal.clone(), station.clone()));
        let hosted = ActorId::hosted_principal(principal.clone(), station);
        let foreign = ActorId::account(AccountId::new(
            principal.clone(),
            DidCoreId::new("ak:did_core:web:station-b.example").unwrap(),
        ));
        assert!(welcome_requester_matches_actor(
            &account,
            &account.to_string()
        ));
        assert!(welcome_requester_matches_actor(
            &hosted,
            &hosted.to_string()
        ));
        assert!(!welcome_requester_matches_actor(
            &account,
            &foreign.to_string()
        ));
        assert!(!welcome_requester_matches_actor(
            &account,
            &hosted.to_string()
        ));
        assert!(!welcome_requester_matches_actor(
            &account,
            principal.as_str()
        ));
    }
}
