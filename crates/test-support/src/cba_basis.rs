//! The accepted governance basis an integration-test Event has to cite.
//!
//! `event-auth-state-resolution.md` §4(1) makes a data-plane Event a DataEvent
//! (`seal_ref` + `auth_context`, never `seal_basis`) and §5 makes a
//! control-plane Event a Control Move (`seal_basis`, never `seal_ref` /
//! `auth_context`). Both forms name a Seal, and for a DataEvent that Seal is
//! not a token: §4.1(3) / §4.3(2) make the verifier resolve the actor's whole
//! effective capability set from the state the Seal covers. soland does exactly
//! that (`capability_refs.rs::data_event_state_at_seal_ref` →
//! `arkret_state::effective_state_at`, which joins the cell log filtered by the
//! Seal's covered Control-Move digests), so an empty Seal authorizes nothing.
//!
//! A fixture Realm that is seeded straight into `AppState` — rather than
//! bootstrapped through `ak.realm.create` over HTTP — therefore has to be given
//! a genuinely sealed genesis unit before any Event it hosts can be admitted.
//! That is what this module builds:
//!
//! 1. the registered `ak.component.realm.authority_root.v1` singleton of `realm-and-space.md` §2.5
//!    — the only authority genesis establishes, whose controller holds effective `ak.realm.owner`;
//! 2. the owner's own first governance grant
//!    ([`soland_services::conformance_basis::OWNER_BOOTSTRAP_GRANT_ACTIONS`]), `issuer == subject`,
//!    one Realm-wide resource selector, a typed `realm_root` authority ref, and the embedded
//!    `capability-action-registry.json` digest;
//! 3. an explicit content grant carrying only requested data-plane actions not already covered by
//!    the owner bootstrap grant.
//!
//! MLS security-frontier admission is independent from this general Event
//! authority basis, which therefore needs exactly one Seal.

use std::collections::BTreeMap;
use std::sync::{LazyLock, Mutex};

use arkret_identifiers::{Did, Hlc, RealmId, SealId};
use arkret_wire::{Seal, SealBasis};
use soland_http::state::AppState;

use crate::AppStateTestExt as _;

/// The notary key every fixture basis Seal is signed with.
const FIXTURE_BASIS_HLC: &str = "0196419b0000-0000-51c0a1ed";
const FIXTURE_BASIS_ID_DOMAIN: &str = "soland:test-support:realm-basis:";
/// Stable MLS group id used by E2EE fixture payloads.
pub const FIXTURE_MLS_GROUP_ID: &str = "fixtureMlsGroup01";

/// One fixture Realm's accepted authorization basis for one subject.
type RealmBasis = soland_services::conformance_basis::ConformanceRealmBasis;

type BasisKey = (String, String, String, Vec<String>);

static REALM_BASES: LazyLock<Mutex<BTreeMap<BasisKey, RealmBasis>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

fn realm_basis(
    realm_id: &str,
    subject: &str,
    notary: &str,
    data_plane_actions: &[&str],
) -> RealmBasis {
    let key = (
        realm_id.to_owned(),
        subject.to_owned(),
        notary.to_owned(),
        data_plane_actions
            .iter()
            .map(|action| (*action).to_owned())
            .collect(),
    );
    REALM_BASES
        .lock()
        .expect("fixture basis cache")
        .entry(key)
        .or_insert_with(|| {
            let actions = data_plane_actions
                .iter()
                .map(|action| (*action).to_owned())
                .collect::<Vec<_>>();
            soland_services::conformance_basis::build_realm_basis(
                realm_id,
                subject,
                soland_services::conformance_basis::RealmBasisFixtureOptions {
                    notary_authority: Some(notary),
                    data_plane_actions: &actions,
                    fixture_id_domain: FIXTURE_BASIS_ID_DOMAIN,
                },
            )
            .expect("fixture Realm basis")
        })
        .clone()
}

/// The Seal a fixture Event names in `seal_ref` / `seal_basis`.
pub fn realm_basis_seal(realm_id: &str, subject: &str, data_plane_actions: &[&str]) -> Seal {
    realm_basis(realm_id, subject, &fixture_notary_did(), data_plane_actions).seal
}

/// The service DID every fixture Realm designates as its notary.
///
/// A Control Move submitted to this service has its proposal receipt minted
/// here, and `NotaryWorker::authority_set_ref_for_events` only issues one when
/// the Realm's notary profile names the service.
fn fixture_notary_did() -> String {
    crate::app_state(crate::app_config()).service_id().clone()
}

/// The single-leaf `seal_basis` a Control Move of `realm_id` cites.
pub fn realm_basis_seal_basis(
    realm_id: &str,
    subject: &str,
    data_plane_actions: &[&str],
) -> SealBasis {
    let seal = realm_basis_seal(realm_id, subject, data_plane_actions);
    SealBasis {
        leaves: vec![seal.id],
        control_event_set_root: seal.control_event_set_root,
        state_root: seal.state_root,
    }
}

/// Put the genesis unit of `realm_id` in place for `subject`.
///
/// A DataEvent `seal_ref` MUST resolve to a verified control-plane Seal of the
/// same Realm (`event-auth-state-resolution.md` §4.3(1)) **and** the governance
/// state that Seal covers MUST authorize the Event's derived writes, so both
/// the Seal object and its sealed cell effects have to exist before the Event
/// is admitted. The cell writes are OR-Set adds under a fixed tag, so repeating
/// this for the same Realm/subject/action set is idempotent.
pub async fn seed_realm_basis(
    state: &AppState,
    realm_id: &str,
    subject: &str,
    data_plane_actions: &[&str],
) -> SealId {
    let realm = RealmId::new(realm_id.to_owned()).expect("fixture Realm id");
    let basis = realm_basis(realm_id, subject, state.service_id(), data_plane_actions);
    state
        .test_put_seal(&basis.seal)
        .expect("fixture basis Seal");
    state
        .test_append_sealed_effects(&realm, &basis.seal.id, &basis.ops)
        .expect("fixture basis sealed effects");
    seed_realm_genesis_event(state, realm_id, subject).await;
    // Accepting a capability Event is what fills the projected grant index the
    // governance predicates read. Sealing the basis directly skips that, so a
    // Realm whose sealed basis plainly grants an action would still answer
    // `missing_capability`.
    for grant in &basis.grants {
        if let Some(grant) =
            soland_domain::reducer::engine_grant_from_cell_body(&grant.grant_id, &grant.body, false)
        {
            state.upsert_projected_grant_for_test(grant);
        }
    }
    basis.seal.id
}

/// Store the Realm's canonical `ak.realm.create`.
///
/// The Control Proposal decision policy is read from this Event, so a Realm
/// without one answers `quorum_unreachable` on every Control Move. A fixture
/// that stands a Realm up out of band still owes it its genesis Event.
pub async fn seed_realm_genesis_event(state: &AppState, realm_id: &str, subject: &str) {
    let genesis_event_id = format!(
        "ak:event:{}",
        realm_id
            .strip_prefix("ak:realm:")
            .expect("fixture Realm id is typed")
    );
    // A Realm has exactly one canonical create and the store enforces that, so
    // do not write another when this Realm already has one — whether from a
    // previous call here or from a fixture that authored its own genesis
    // Event. The reducer projection is checked separately below: fixtures that
    // write persistence directly still have to materialize the authority root
    // used by authorization predicates.
    let genesis_is_stored = state
        .test_persistence()
        .events()
        .realm_events_newest_first(realm_id)
        .await
        .expect("fixture Realm genesis lookup")
        .iter()
        .any(|record| record.kind == arkret_wire::EventKind::REALM_CREATE);
    let created_at = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
        .expect("fixture genesis timestamp")
        .with_timezone(&chrono::Utc);
    let payload = serde_json::json!({
        "object": {
            "id": realm_id,
            "schema": "ak.schema.realm.v1",
            "title": "Fixture Realm",
            "summary": "Soland integration-test Realm",
            "created_by": subject,
            "trust_domain": "ak:trust_domain:soland.test",
            "schema_refs": ["ak.schema.realm.v1"],
            "default_discoverability": "unlisted",
            "default_join_rule": "invite",
            "history_visibility": "shared",
            "encryption_profile": "none",
            "security_class": "standard",
            "federation_policy": "restricted",
            "notary_profile": "single_did",
            "digest_algorithm": "sha256",
            "capability_action_registry_digest":
                arkret_policy::current_capability_action_registry_digest()
                    .expect("fixture capability action registry digest"),
            "notary": {
                "kind": "single_did",
                "did": state.service_id(),
                "recovery_members": [],
                "controller_organization": subject,
                "recovery_controller_organizations": []
            },
            "created_at": arkret_canonical::format_timestamp_canonical(created_at)
        }
    });
    let mut event = arkret_wire::Event::new_with_id_at(
        arkret_wire::EventId::new(genesis_event_id.clone()).expect("fixture genesis Event id"),
        arkret_wire::EventKind::REALM_CREATE,
        arkret_wire::ScopeRef::Realm {
            realm_id: RealmId::new(realm_id.to_owned()).expect("fixture Realm id"),
        },
        Did::new(subject.to_owned()).expect("fixture genesis actor DID"),
        0,
        Hlc::new(FIXTURE_BASIS_HLC).expect("fixture genesis HLC"),
        payload.clone(),
        created_at,
    )
    .expect("fixture genesis Event");
    event.event_id =
        arkret_wire::EventId::new(genesis_event_id.clone()).expect("fixture genesis Event id");
    let canonical_digest = event.event_digest().expect("fixture genesis Event digest");
    if !genesis_is_stored {
        state
            .test_persistence()
            .events()
            .put(soland_storage::CanonicalEventRecord {
                event_id: genesis_event_id.clone(),
                actor_id: subject.to_owned(),
                actor_seq: 0,
                realm_id: Some(realm_id.to_owned()),
                kind: arkret_wire::EventKind::REALM_CREATE.to_owned(),
                schema_id: "ak.schema.event.v1".to_owned(),
                canonical_digest,
                canonical_bytes: Vec::new(),
                envelope: serde_json::to_value(&event).expect("fixture genesis envelope"),
                received_at: chrono::Utc::now(),
            })
            .await
            .expect("fixture Realm genesis Event");
    }

    let projection = state.test_projection();
    let mut projection = projection.lock();
    if projection.realm_authority_root(realm_id).is_none() {
        let writes = arkret_schema::project_registered_cell_writes(
            &event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .expect("fixture genesis registered projection");
        let operation = arkret_event_draft::Operation::create(
            arkret_identifiers::OperationId::new(format!(
                "ak:operation:{}",
                realm_id
                    .strip_prefix("ak:realm:")
                    .expect("fixture Realm id is typed")
            ))
            .expect("fixture genesis Operation id"),
            RealmId::new(realm_id.to_owned()).expect("fixture Realm id"),
            arkret_wire::EventKind::REALM_CREATE,
            payload,
        );
        let effect = projection.apply_projected(&operation, &writes, state.test_hlc());
        assert!(
            projection.realm_authority_root(realm_id).is_some(),
            "fixture genesis must project its authority root, got {effect:?}"
        );
    }
}

/// Give `event` the CBA envelope shape its kind's registry row declares.
///
/// `event-auth-state-resolution.md` §3 puts `plane` on the cell family, and the
/// event-kind registry row carries the plane every derived write of that kind
/// lands in — the same descriptor soland's admission reads through
/// `arkret_schema::validate_registered_cell_writes_in_context`.
///
/// Two closed exceptions carry no basis field at all and are listed by §5, not
/// derived from the kind's plane: the `ak.realm.create` genesis anchor unit and
/// the B-model `ak.device.reanchor`, which fixes its frontier in
/// `payload.pre_fence_basis`. Non-reducer-input kinds carry no CBA field either
/// (`Event::validate_for_submit_structural`).
pub fn apply_registered_cba_plane(
    event: &mut arkret_wire::Event,
    verification_method: &str,
    data_plane_actions: &[&str],
) {
    let Some(descriptor) = event.kind.descriptor().filter(|row| row.reducer_input) else {
        return;
    };
    if matches!(
        event.kind.as_str(),
        arkret_wire::EventKind::REALM_CREATE | "ak.device.reanchor"
    ) {
        return;
    }
    let basis = realm_basis_seal(
        event.realm_id.as_str(),
        event.actor_id.as_str(),
        data_plane_actions,
    );
    match descriptor.plane {
        Some("data") => {
            event.seal_ref = Some(basis.id);
            event.auth_context = Some(arkret_wire::AuthContext {
                did: event.actor_id.clone(),
                key_id: verification_method
                    .split_once('#')
                    .map_or_else(|| verification_method.to_owned(), |(_, key)| key.to_owned()),
                key_epoch: 0,
                credential_epoch: None,
            });
        }
        Some("control") => {
            event.seal_basis = Some(SealBasis {
                leaves: vec![basis.id],
                control_event_set_root: basis.control_event_set_root,
                state_root: basis.state_root,
            });
        }
        _ => {}
    }
}
