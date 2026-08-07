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
/// The recovery notary a fixture Realm names, and the organization controlling
/// it. The organization is deliberately not the Realm creator's: `single_did`
/// recovery diversity is only satisfied when they differ.
const FIXTURE_NOTARY_RECOVERY_MEMBER: &str = "did:web:recovery.notary.example";
const FIXTURE_NOTARY_RECOVERY_ORGANIZATION: &str = "did:web:recovery.organization.example";

/// One fixture Realm's accepted authorization basis for one subject.
pub type RealmBasis = soland_services::conformance_basis::ConformanceRealmBasis;

/// One fixture family's basis identity.
///
/// A basis is only useful if the Seal an Event *names* is the Seal the fixture
/// *sealed*, so both sides have to agree on the id domain the synthetic grants
/// are minted in and on the actions the Realm basis grants. Making that pair
/// explicit is what lets several fixture families share this module without
/// silently renumbering each other's Seals.
#[derive(Clone, Copy, Debug)]
pub struct FixtureBasis<'a> {
    pub id_domain: &'a str,
    pub data_plane_actions: &'a [&'a str],
}

impl<'a> FixtureBasis<'a> {
    /// This crate's own fixture family.
    #[must_use]
    pub const fn shared(data_plane_actions: &'a [&'a str]) -> Self {
        Self {
            id_domain: FIXTURE_BASIS_ID_DOMAIN,
            data_plane_actions,
        }
    }

    /// A fixture family that mints its grants in its own id domain.
    #[must_use]
    pub const fn in_domain(id_domain: &'a str, data_plane_actions: &'a [&'a str]) -> Self {
        Self {
            id_domain,
            data_plane_actions,
        }
    }
}

type BasisKey = (String, String, String, String, Vec<String>);

static REALM_BASES: LazyLock<Mutex<BTreeMap<BasisKey, RealmBasis>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

/// The sealed genesis unit `subject` holds in `realm_id`.
pub fn realm_basis(
    realm_id: &str,
    subject: &str,
    notary: &str,
    basis: FixtureBasis<'_>,
) -> RealmBasis {
    let actions = basis
        .data_plane_actions
        .iter()
        .map(|action| (*action).to_owned())
        .collect::<Vec<_>>();
    let key = (
        realm_id.to_owned(),
        subject.to_owned(),
        notary.to_owned(),
        basis.id_domain.to_owned(),
        actions.clone(),
    );
    REALM_BASES
        .lock()
        .expect("fixture basis cache")
        .entry(key)
        .or_insert_with(|| {
            soland_services::conformance_basis::build_realm_basis(
                realm_id,
                subject,
                soland_services::conformance_basis::RealmBasisFixtureOptions {
                    notary_authority: Some(notary),
                    data_plane_actions: &actions,
                    fixture_id_domain: basis.id_domain,
                },
            )
            .expect("fixture Realm basis")
        })
        .clone()
}

/// The Seal a fixture Event names in `seal_ref` / `seal_basis`.
pub fn realm_basis_seal(realm_id: &str, subject: &str, basis: FixtureBasis<'_>) -> Seal {
    realm_basis(realm_id, subject, &fixture_notary_did(), basis).seal
}

/// The fixture basis Seal an already-built Event cites.
///
/// Federation disclosure is keyed off the transported Event, not off its actor:
/// a `cba_proof_bundles` entry has to be reachable from some transported
/// `seal_ref` or `seal_basis.leaves` entry. So a fixture that re-authors an
/// Event after the envelope was built has to disclose the Seal the envelope
/// still names, whichever fixture family minted it.
#[must_use]
pub fn basis_seal_with_id(seal_id: &SealId) -> Option<Seal> {
    REALM_BASES
        .lock()
        .expect("fixture basis cache")
        .values()
        .find(|basis| basis.seal.id == *seal_id)
        .map(|basis| basis.seal.clone())
}

/// The service DID every fixture Realm designates as its notary.
///
/// A Control Move submitted to this service has its Control Proposal Ack minted
/// here, and `NotaryWorker::authority_set_ref_for_events` only issues one when
/// the Realm's notary profile names the service.
fn fixture_notary_did() -> String {
    crate::app_state(crate::app_config()).service_id().clone()
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
    fixture_basis: FixtureBasis<'_>,
) -> SealId {
    let realm = RealmId::new(realm_id.to_owned()).expect("fixture Realm id");
    let basis = realm_basis(realm_id, subject, state.service_id(), fixture_basis);
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

/// The `ak.realm.create` payload a fixture Realm's genesis Event carries.
///
/// `realm-and-space.md` section 2.5 makes the genesis Event the sole writer of
/// the Realm's registered cells, and `realm_create_payload` requires every field
/// they derive from — `reducer_profile` included, which admission then reads off
/// `ak.component.realm.reducer_profile.v1` for every later Event in the Realm.
/// The object carries no `id`: the Realm id is derived from the Event.
///
/// This is shared rather than restated per fixture because a partial payload
/// does not fail as "this fixture is incomplete" — it fails as a 400 on the
/// genesis submit, several layers away from whatever the test was about.
///
/// The `single_did` notary carries real recovery evidence: `realm.schema.json`
/// requires `recovery_members` and `recovery_controller_organizations` to be
/// non-empty, and the reducer requires at least one recovery controller
/// organization to differ from `controller_organization` — a single-organization
/// recovery setup is exactly what that rule rejects. A fixture that seeded
/// empty arrays only got away with it because it wrote straight to persistence
/// and never met the schema.
#[must_use]
pub fn realm_genesis_payload(
    subject: &str,
    notary_did: &str,
    title: &str,
    trust_domain: &str,
    created_at: chrono::DateTime<chrono::Utc>,
) -> serde_json::Value {
    serde_json::json!({
        "object": {
            "schema": "ak.schema.realm.v1",
            "title": title,
            "summary": "Soland integration-test Realm",
            "created_by": subject,
            "reducer_profile": arkret_wire::CORE_REDUCER_PROFILE,
            "trust_domain": trust_domain,
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
                "did": notary_did,
                "recovery_members": [FIXTURE_NOTARY_RECOVERY_MEMBER],
                "controller_organization": subject,
                "recovery_controller_organizations": [FIXTURE_NOTARY_RECOVERY_ORGANIZATION]
            },
            "created_at": arkret_canonical::format_timestamp_canonical(created_at)
        }
    })
}

/// Store the Realm's canonical `ak.realm.create`.
///
/// The Control Proposal decision policy is read from this Event, so a Realm
/// without one answers `quorum_unreachable` on every Control Move. A fixture
/// that stands a Realm up out of band still owes it its genesis Event.
pub async fn seed_realm_genesis_event(state: &AppState, realm_id: &str, subject: &str) {
    // The genesis Event id has to be the one this Realm id derives from, or a
    // receiver that re-derives `realm_id` from the Event lands on a different
    // Realm than the fixture stood up — which is exactly what admission checks.
    //
    // Two branches, matching `arkret_wire::derive_genesis_realm_id`. A
    // collaboration Realm id shares the create Event's UUID payload, so retype
    // it back. A Principal Control Realm id is subject-derived from its
    // principal DID and carries the UUIDv7 layout — not a legal Event id at all
    // — but that branch ignores the Event id, so any well-formed one will do.
    let realm_uuid = realm_id
        .strip_prefix("ak:realm:")
        .expect("fixture Realm id is typed");
    let is_principal_control_realm = realm_uuid.as_bytes().get(14) != Some(&b'8');
    let genesis_event_id = if is_principal_control_realm {
        crate::fixture_content_bound_id("ak:event:")
    } else {
        format!("ak:event:{realm_uuid}")
    };
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
    let mut payload = realm_genesis_payload(
        subject,
        state.service_id(),
        "Fixture Realm",
        "ak:trust_domain:soland.test",
        created_at,
    );
    if is_principal_control_realm {
        payload["object"]["fields"] = serde_json::json!({"purpose": "principal_control"});
    }
    let payload = payload;
    let mut event = arkret_wire::Event::new_with_id_at(
        arkret_wire::EventId::new(genesis_event_id.clone()).expect("fixture genesis Event id"),
        arkret_wire::EventKind::REALM_CREATE,
        arkret_wire::ScopeRef::RealmGenesis,
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
            arkret_identifiers::OperationId::new(arkret_identifiers::new_prefixed_uuid7(
                "ak:operation:",
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
    basis: FixtureBasis<'_>,
) {
    if !carries_a_cba_basis(event) {
        return;
    }
    let seal = realm_basis_seal(event.realm_id.as_str(), event.actor_id.as_str(), basis);
    apply_registered_cba_plane_seal(event, verification_method, seal.id);
}

/// Give `event` the CBA envelope shape its kind's registry row declares, citing
/// a Seal this deployment already accepted.
///
/// A Realm bootstrapped through the real `ak.realm.create` batch has a genuine
/// accepted Seal on its frontier, and its Moves have to cite *that* — the
/// synthetic basis of [`realm_basis_seal`] belongs to a Realm that was stood up
/// straight in `AppState` and covers nothing the notary ever sealed.
pub fn apply_registered_cba_plane_seal(
    event: &mut arkret_wire::Event,
    verification_method: &str,
    seal_id: SealId,
) {
    if !carries_a_cba_basis(event) {
        return;
    }
    let plane = event
        .kind
        .descriptor()
        .and_then(|descriptor| descriptor.plane);
    match plane {
        Some("data") => {
            event.seal_ref = Some(seal_id);
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
                leaves: vec![seal_id],
            });
        }
        _ => {}
    }
}

/// Whether `event`'s kind owes a CBA basis field at all.
fn carries_a_cba_basis(event: &arkret_wire::Event) -> bool {
    event.kind.descriptor().is_some_and(|row| row.reducer_input)
        && !matches!(
            event.kind.as_str(),
            arkret_wire::EventKind::REALM_CREATE | "ak.device.reanchor"
        )
}
