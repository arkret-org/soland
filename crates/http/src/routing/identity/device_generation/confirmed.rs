use std::collections::BTreeSet;
use std::sync::Arc;

use arkret_event_draft::EventPayloadExt as _;
use arkret_state::ordinary_history::HistoryEvidenceError;
use arkret_wire::{AccountId, ActorId};

use crate::state::AppState;

fn unavailable(error: impl std::fmt::Display) -> HistoryEvidenceError {
    HistoryEvidenceError::Unavailable(error.to_string())
}

fn invalid(error: impl std::fmt::Display) -> HistoryEvidenceError {
    HistoryEvidenceError::Invalid(error.to_string())
}

fn webvh_registration_anchor(
    did: &arkret_wire::Did,
    seq: u64,
    operation: &serde_json::Value,
) -> Result<arkret_models_identity::PrincipalRegistrationAnchor, HistoryEvidenceError> {
    let operation: std::collections::BTreeMap<String, serde_json::Value> =
        serde_json::from_value(operation.clone()).map_err(invalid)?;
    let normalized_did_document = operation
        .get("state")
        .cloned()
        .ok_or_else(|| invalid("registered DID inception omits its state"))
        .and_then(|state| serde_json::from_value(state).map_err(invalid))?;
    let anchor = arkret_models_identity::PrincipalRegistrationAnchor::WebvhRegistration {
        registration_did_operation: Box::new(
            arkret_models_identity::DidOperationSubmitRequestBody {
                did: did.clone(),
                did_method: arkret_models_identity::DidMethodName::Webvh,
                seq: Some(seq),
                prev_event_digest: None,
                operation: operation.clone(),
            },
        ),
        log_entries: vec![operation],
        witness_records: Vec::new(),
        normalized_did_document,
    };
    arkret_identity::validate_principal_registration_anchor(&anchor).map_err(invalid)?;
    Ok(anchor)
}

/// Load only local canonical material. No directory request, origin fetch or
/// evidence TTL participates in reconstructing this confirmed source history.
/// The durable Account/PCR binding selects the genesis; its independently
/// verified inception root authenticates the initial notary commitment.
pub(crate) async fn load_confirmed_device_history(
    state: &AppState,
    account: &AccountId,
) -> Result<Option<Arc<arkret::DeviceAuthorizationHistory>>, HistoryEvidenceError> {
    if account.station_id != state.service_core_id() {
        return Err(invalid(
            "device inventory belongs to a different Station Account",
        ));
    }
    let Some(binding) = state
        .persistence()
        .principal_resolution_by_account_id(account)
        .await
        .map_err(unavailable)?
    else {
        return Ok(None);
    };
    let Some(head) = state
        .projections()
        .realm_seal_head(&binding.pcr_realm_id)
        .await
        .map_err(unavailable)?
    else {
        // Pending genesis has no active device generation. Its first Seal is
        // authenticated by the separate closed founding-device path. A store
        // error/quarantined head above remains unavailable, never this branch.
        return Ok(None);
    };
    if let Some(history) = state.device_history_cache.lock().await.get(account)
        && history.confirmed_head() == &head
    {
        return Ok(Some(history.clone()));
    }
    let genesis = &binding.genesis_event;
    if binding.account_id != *account
        || genesis.realm_id != binding.pcr_realm_id
        || genesis.actor_id != ActorId::account(account.clone())
        || genesis.executed_by.is_some()
    {
        return Err(invalid(
            "registered PCR genesis does not bind the local Account",
        ));
    }
    let create = genesis
        .typed_payload::<arkret_wire::event_spec::RealmCreate>()
        .map_err(invalid)?;
    let initial = create
        .object
        .initial_resolution
        .as_ref()
        .ok_or_else(|| unavailable("registered PCR inception resolution is missing"))?;
    let entries = state
        .dids()
        .log_events(initial.did.as_str())
        .await
        .map_err(unavailable)?;
    let mut inception_entries = entries.iter().filter(|entry| entry.seq == 1);
    let entry = inception_entries
        .next()
        .ok_or_else(|| unavailable("registered PCR original DID inception is missing"))?;
    if inception_entries.next().is_some() || entry.did != initial.did.as_str() {
        return Err(invalid(
            "DID inception storage has an ambiguous subject or entry",
        ));
    }
    let registration_anchor = webvh_registration_anchor(&initial.did, entry.seq, &entry.operation)?;
    let root = arkret_identity::validate_principal_registration_anchor(&registration_anchor)
        .map_err(invalid)?;
    if root.principal_id != account.principal_id {
        return Err(invalid(
            "DID inception root does not authenticate the selected Account",
        ));
    }
    let Some(proof) = genesis.producer_proof.as_ref() else {
        return Err(invalid(
            "PCR genesis requires its unique inception-root proof",
        ));
    };
    proof.validate_production().map_err(invalid)?;
    if proof.verification_method != root.root_verification_method
        || proof.created_at != genesis.created_at
    {
        return Err(invalid(
            "PCR genesis proof differs from its authenticated root",
        ));
    }
    let suite = create.object.digest_algorithm;
    genesis
        .verify_event_id_matches_content_with_digest_suite(suite)
        .map_err(invalid)?;
    let root_key = arkret_canonical::decode_ed25519_multibase(&root.root_public_key_multibase)
        .map_err(invalid)?;
    let bytes = arkret_signatures::proof::EventProofBuilder::new()
        .envelope_bytes(genesis)
        .map_err(invalid)?;
    arkret_signatures::proof::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &bytes,
        &genesis.actor_id,
        &arkret_signatures::proof::PublicKeyMaterial::Ed25519Raw {
            bytes: root_key.to_vec(),
        },
        suite,
    )
    .map_err(invalid)?;
    // Only now is the notary commitment authenticated independently of any
    // candidate Seal. The shared adapter rechecks the complete founding unit.
    let trusted_notary = &create.object.notary;
    let mut seals = Vec::new();
    let mut seen = BTreeSet::new();
    let mut next = Some(head.clone());
    while let Some(id) = next {
        if !seen.insert(id.clone()) {
            return Err(invalid("confirmed PCR prefix contains a cycle"));
        }
        let seal = state
            .projections()
            .seal_by_id(&id)
            .await
            .map_err(unavailable)?
            .ok_or_else(|| unavailable("confirmed PCR Seal material is missing"))?;
        if seal.realm_id != binding.pcr_realm_id {
            return Err(invalid("confirmed PCR prefix crosses a Realm boundary"));
        }
        next = seal.predecessor_ref.clone();
        seals.push(seal);
    }
    seals.reverse();
    let events = state
        .projections()
        .confirmed_command_events(&binding.pcr_realm_id)
        .await
        .map_err(unavailable)?;
    let history = arkret::DeviceAuthorizationHistory::verify(
        account,
        &genesis.event_id,
        trusted_notary,
        &registration_anchor,
        &head,
        &seals,
        &events,
        suite,
    )?;
    let mut cache = state.device_history_cache.lock().await;
    if state
        .projections()
        .realm_seal_head(&binding.pcr_realm_id)
        .await
        .map_err(unavailable)?
        .as_ref()
        != Some(&head)
    {
        return Err(unavailable(
            "confirmed PCR advanced while device history was reconstructed",
        ));
    }
    // A writer must still check this exact head under the durable Realm lock.
    let history = Arc::new(history);
    cache.insert(account.clone(), history.clone());
    Ok(Some(history))
}

/// Build the device-Control projection that must commit atomically with one
/// candidate PCR Seal. Non-PCR Realms return `None`; once a Realm is bound as a
/// local PCR, missing or inconsistent history is an error and the Seal must not
/// become visible without its portable signer roots.
pub(crate) async fn candidate_device_control_projection(
    state: &AppState,
    candidate: &arkret_wire::Seal,
    suite: arkret_canonical::DigestSuite,
) -> Result<Option<soland_storage::ConfirmedDeviceControlProjection>, HistoryEvidenceError> {
    let Some(binding) = state
        .persistence()
        .principal_resolution_for_realm(&candidate.realm_id)
        .await
        .map_err(unavailable)?
    else {
        return Ok(None);
    };
    let account = &binding.account_id;
    let genesis = &binding.genesis_event;
    if binding.pcr_realm_id != candidate.realm_id || genesis.realm_id != candidate.realm_id {
        return Err(invalid(
            "candidate signer projection crosses its registered control Realm",
        ));
    }
    let create = genesis
        .typed_payload::<arkret_wire::event_spec::RealmCreate>()
        .map_err(invalid)?;
    if create.object.purpose
        != arkret_models_collaboration::events_payloads::RealmPurpose::PrincipalControl
    {
        return Ok(None);
    }
    if account.station_id != state.service_core_id()
        || genesis.actor_id != ActorId::account(account.clone())
        || genesis.executed_by.is_some()
    {
        return Err(invalid(
            "candidate PCR Seal does not bind the local Account authority",
        ));
    }
    if create.object.digest_algorithm != suite {
        return Err(invalid(
            "candidate PCR Seal digest suite differs from its genesis",
        ));
    }
    let initial = create
        .object
        .initial_resolution
        .as_ref()
        .ok_or_else(|| unavailable("registered PCR inception resolution is missing"))?;
    let entries = state
        .dids()
        .log_events(initial.did.as_str())
        .await
        .map_err(unavailable)?;
    let mut inception_entries = entries.iter().filter(|entry| entry.seq == 1);
    let entry = inception_entries
        .next()
        .ok_or_else(|| unavailable("registered PCR original DID inception is missing"))?;
    if inception_entries.next().is_some() || entry.did != initial.did.as_str() {
        return Err(invalid(
            "DID inception storage has an ambiguous subject or entry",
        ));
    }
    let registration_anchor = webvh_registration_anchor(&initial.did, entry.seq, &entry.operation)?;
    let root = arkret_identity::validate_principal_registration_anchor(&registration_anchor)
        .map_err(invalid)?;
    if root.principal_id != account.principal_id {
        return Err(invalid(
            "DID inception root does not authenticate the selected Account",
        ));
    }
    let Some(proof) = genesis.producer_proof.as_ref() else {
        return Err(invalid(
            "PCR genesis requires its unique inception-root proof",
        ));
    };
    proof.validate_production().map_err(invalid)?;
    if proof.verification_method != root.root_verification_method
        || proof.created_at != genesis.created_at
    {
        return Err(invalid(
            "PCR genesis proof differs from its authenticated root",
        ));
    }
    genesis
        .verify_event_id_matches_content_with_digest_suite(suite)
        .map_err(invalid)?;
    let root_key = arkret_canonical::decode_ed25519_multibase(&root.root_public_key_multibase)
        .map_err(invalid)?;
    let bytes = arkret_signatures::proof::EventProofBuilder::new()
        .envelope_bytes(genesis)
        .map_err(invalid)?;
    arkret_signatures::proof::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &bytes,
        &genesis.actor_id,
        &arkret_signatures::proof::PublicKeyMaterial::Ed25519Raw {
            bytes: root_key.to_vec(),
        },
        suite,
    )
    .map_err(invalid)?;

    let mut seals = Vec::new();
    let mut seen_seals = BTreeSet::new();
    let mut next = Some(candidate.clone());
    while let Some(seal) = next {
        if !seen_seals.insert(seal.id.clone()) {
            return Err(invalid("candidate PCR Seal prefix contains a cycle"));
        }
        if seal.realm_id != candidate.realm_id {
            return Err(invalid(
                "candidate PCR Seal prefix crosses a Realm boundary",
            ));
        }
        next = match seal.predecessor_ref.as_ref() {
            Some(predecessor) => Some(
                state
                    .projections()
                    .seal_by_id(predecessor)
                    .await
                    .map_err(unavailable)?
                    .ok_or_else(|| unavailable("candidate PCR predecessor Seal is missing"))?,
            ),
            None => None,
        };
        seals.push(seal);
    }
    seals.reverse();
    let mut events = Vec::new();
    let mut seen_events = BTreeSet::new();
    for seal in &seals {
        for result in &seal.command_results {
            if result.outcome != arkret_wire::CommandOutcome::Committed {
                continue;
            }
            for digest in &result.unit_event_digests {
                let event = state
                    .projections()
                    .control_event_by_digest(digest)
                    .await
                    .map_err(unavailable)?
                    .ok_or_else(|| unavailable("candidate PCR committed Event is missing"))?;
                if event.realm_id != candidate.realm_id
                    || event.event_id.event_digest() != *digest
                    || !seen_events.insert(event.event_id.clone())
                {
                    return Err(invalid(
                        "candidate PCR committed Event identity or uniqueness is invalid",
                    ));
                }
                events.push(event);
            }
        }
    }
    let history = arkret::DeviceAuthorizationHistory::verify(
        account,
        &genesis.event_id,
        &create.object.notary,
        &registration_anchor,
        &candidate.id,
        &seals,
        &events,
        suite,
    )?;
    soland_storage::ConfirmedDeviceControlProjection::from_verified_history(
        history,
        &registration_anchor,
        &seals,
        &events,
        suite,
    )
    .map(Some)
    .map_err(invalid)
}
