//! HTTP-aware installation of signed device-history fixtures.
//!
//! This lives outside `device_authorization_history`: storage adapter unit
//! tests include that lower-level source file directly and must not acquire a
//! dependency on Soland's HTTP or service layers.

use std::collections::{BTreeMap, BTreeSet};

use arkret_canonical::DigestSuite;
use arkret_identifiers::Hash;
use arkret_state::state::ControlProposalIngress;
use arkret_wire::{ControlProposalAck, ControlProposalDecisionPolicy};

use crate::device_authorization_history::DeviceHistoryFixture;

/// Commit the fixture through the same registered-unit and atomic Seal path
/// used by PostgreSQL governance.
pub async fn commit_confirmed_history_fixture(
    state: &soland_http::state::AppState,
    fixture: &DeviceHistoryFixture,
) -> Result<(), String> {
    commit_confirmed_history_fixture_from(state, fixture, 0).await
}

/// Commit only the Seal suffix beginning at `first_seal_index`.
///
/// Every Seal gets a freshly verified history prefix and the matching complete
/// generic-Control root set. No test may publish a Seal first and repair its
/// device projection later.
pub async fn commit_confirmed_history_fixture_from(
    state: &soland_http::state::AppState,
    fixture: &DeviceHistoryFixture,
    first_seal_index: usize,
) -> Result<(), String> {
    if first_seal_index > fixture.seals.len() {
        return Err(format!(
            "fixture Seal suffix starts at {first_seal_index}, but only {} Seals exist",
            fixture.seals.len()
        ));
    }
    let (control_events, committer) = {
        let registry = crate::state_test_registry().lock();
        let resources = registry
            .get(&crate::app_state_key(state))
            .ok_or_else(|| "AppState was not constructed by soland-test-support".to_owned())?;
        (
            resources
                .control_event_store
                .clone()
                .ok_or_else(|| "test Control Event store is unavailable".to_owned())?,
            resources
                .event_seal_committer
                .clone()
                .ok_or_else(|| "test atomic Seal committer is unavailable".to_owned())?,
        )
    };
    let signer = soland_services::identity::FrozenEd25519NotarySigner::from_seed(
        fixture.notary_signing_seed,
        fixture.did.clone(),
        fixture.configuration.signer.verification_method.clone(),
    );
    let authority_set_ref = Hash::new(
        arkret_canonical::canonical_sha256(&fixture.configuration)
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let by_digest = fixture
        .events
        .iter()
        .map(|event| (event.event_id.event_digest(), event))
        .collect::<BTreeMap<_, _>>();
    let mut covered = fixture.seals[..first_seal_index]
        .iter()
        .flat_map(|seal| {
            seal.covered_event_digests
                .iter()
                .chain(seal.delta.iter())
                .cloned()
        })
        .collect::<BTreeSet<_>>();

    for (seal_index, seal) in fixture.seals.iter().enumerate().skip(first_seal_index) {
        for result in &seal.command_results {
            let mut members = Vec::with_capacity(result.unit_event_digests.len());
            for digest in &result.unit_event_digests {
                let event = by_digest
                    .get(digest)
                    .ok_or_else(|| format!("fixture Seal names missing Control Event {digest}"))?;
                let ack = ControlProposalAck::issue_with_signer(
                    seal.realm_id.clone(),
                    digest.clone(),
                    authority_set_ref.clone(),
                    event.created_at,
                    ControlProposalDecisionPolicy::default(),
                    &signer,
                )
                .map_err(|error| error.to_string())?;
                members.push(arkret_state::state::ControlUnitIngressMember {
                    event: (*event).clone(),
                    digest_suite: DigestSuite::Sha256,
                    ingress: ControlProposalIngress::AckRequired(ack),
                });
            }
            control_events
                .put_pending_unit_with_ingress(&members)
                .await
                .map_err(|error| error.to_string())?;
        }
        covered.extend(seal.covered_event_digests.iter().cloned());
        covered.extend(seal.delta.iter().cloned());
        let prefix_events = fixture
            .events
            .iter()
            .filter(|event| covered.contains(&event.event_id.event_digest()))
            .cloned()
            .collect::<Vec<_>>();
        let prefix_seals = &fixture.seals[..=seal_index];
        let verified_prefix = arkret::DeviceAuthorizationHistory::verify(
            &fixture.account,
            &fixture.events[0].event_id,
            &fixture.configuration,
            &fixture.registration_anchor,
            &seal.id,
            prefix_seals,
            &prefix_events,
            DigestSuite::Sha256,
        )
        .map_err(|error| format!("verify fixture history prefix at {}: {error}", seal.id))?;
        let confirmed_device_control =
            soland_storage::ConfirmedDeviceControlProjection::from_verified_history(
                verified_prefix,
                &fixture.registration_anchor,
                prefix_seals,
                &prefix_events,
                DigestSuite::Sha256,
            )
            .map_err(|error| format!("build fixture Control projection at {}: {error}", seal.id))?;
        let ops = fixture
            .sealed_ops
            .get(seal_index)
            .ok_or_else(|| format!("fixture Seal {seal_index} has no matching committed ops"))?;
        if !committer
            .commit_if_head(
                seal,
                DigestSuite::Sha256,
                seal.predecessor_ref.as_ref(),
                ops,
                &covered,
                &[],
                Some(&confirmed_device_control),
            )
            .await
            .map_err(|error| error.to_string())?
        {
            return Err(format!("fixture Seal {} frontier changed", seal.id));
        }
    }
    Ok(())
}
