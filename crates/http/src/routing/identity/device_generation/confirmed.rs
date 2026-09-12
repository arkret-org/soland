use std::collections::BTreeSet;

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

/// Load only local canonical material. No directory request, origin fetch or
/// evidence TTL participates in reconstructing this confirmed source history.
/// The durable Account/PCR binding selects the genesis; its independently
/// verified inception root authenticates the initial notary commitment.
pub(crate) async fn load_confirmed_device_history(
    state: &AppState,
    account: &AccountId,
) -> Result<Option<arkret::DeviceAuthorizationHistory>, HistoryEvidenceError> {
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
    let inception = arkret_models_identity::DidOperationSubmitRequestBody {
        did: initial.did.clone(),
        did_method: arkret_models_identity::DidMethodName::Webvh,
        seq: Some(entry.seq),
        prev_event_digest: None,
        operation: serde_json::from_value(entry.operation.clone()).map_err(invalid)?,
    };
    let root = arkret_signatures::webvh::validate_principal_inception_operation(&inception)
        .map_err(invalid)?;
    if root.principal_id != account.principal_id {
        return Err(invalid(
            "DID inception root does not authenticate the selected Account",
        ));
    }
    let [proof] = genesis.proofs.as_slice() else {
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
        &inception,
        &head,
        &seals,
        &events,
        suite,
    )?;
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
    Ok(Some(history))
}
