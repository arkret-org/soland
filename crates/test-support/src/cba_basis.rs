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

use arkret_identifiers::{DidFullId, Hlc, RealmId, SealId};
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
const FIXTURE_NOTARY_RECOVERY_MEMBER: &str = "ak:did_core:web:recovery.notary.example";
const FIXTURE_NOTARY_RECOVERY_ORGANIZATION: &str = "ak:did_core:web:recovery.organization.example";

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

fn fixture_pcr_founding_device_descriptor(
    principal: &arkret_identifiers::DidCoreId,
    created_at: chrono::DateTime<chrono::Utc>,
) -> arkret_models_collaboration::events_payloads::FoundingDeviceDescriptor {
    use arkret_models_collaboration::events_payloads::device_identity::{
        DeviceAuthorizationBindingKind, DeviceAuthorizePayload, DeviceOrPrincipalRef,
        device_authorize_payload_digest,
    };
    use arkret_models_collaboration::events_payloads::{
        FoundingDeviceHpkeKeyAlgorithm, FoundingDeviceKeyAlgorithm, FoundingDeviceKeyPurpose,
        SignatureMaterial,
    };

    let device_id = arkret_identifiers::DeviceId::new(
        "ak:device:01904100-0000-7000-8000-000000000001".to_owned(),
    )
    .expect("fixture PCR device id");
    let device_public_key = arkret_wire::NonEmptyString::new(
        "did:key:z6MkvMW3tjuvW6PqYiX8dLRNwZWyGhxe3biRDjA4ZPiBaFaJ".to_owned(),
    )
    .expect("fixture PCR device key");
    let hpke_key = arkret_wire::NonEmptyString::new("z6LSDeviceHpkeKey".to_owned())
        .expect("fixture PCR HPKE key");
    let algorithms = vec![
        arkret_wire::NonEmptyString::new("ak.hpke_x25519_aead_chacha20poly1305.v1".to_owned())
            .expect("fixture PCR algorithm"),
    ];
    let authorize = DeviceAuthorizePayload {
        principal_id: principal.clone(),
        device_id: device_id.clone(),
        device_public_key: device_public_key.clone(),
        hpke_key: hpke_key.clone(),
        algorithms: algorithms.clone(),
        device_key_algorithm: Some(arkret_wire::NonEmptyString::new("Ed25519").unwrap()),
        authorized_by: DeviceOrPrincipalRef::Principal(principal.clone()),
        scopes: None,
        not_before: created_at,
        expires_at: None,
        authorization_binding_kind: DeviceAuthorizationBindingKind::RootAnchored,
        device_signature: SignatureMaterial::NonEmptyString(
            arkret_wire::NonEmptyString::new("fixture-signature").unwrap(),
        ),
        recovery_session_id: None,
    };
    let authorize = serde_json::to_value(authorize).expect("fixture PCR authorize payload");
    arkret_models_collaboration::events_payloads::FoundingDeviceDescriptor {
        descriptor_version: 1,
        device_id,
        device_key_digest: arkret_wire::Hash::new(arkret_canonical::sha256_digest(
            device_public_key.as_bytes(),
        ))
        .unwrap(),
        device_public_key,
        device_key_algorithm: FoundingDeviceKeyAlgorithm::Ed25519,
        device_key_purpose: FoundingDeviceKeyPurpose::EventSigningAndMlsIdentity,
        hpke_key_digest: arkret_wire::Hash::new(arkret_canonical::sha256_digest(
            hpke_key.as_bytes(),
        ))
        .unwrap(),
        hpke_key,
        hpke_key_algorithm: FoundingDeviceHpkeKeyAlgorithm::X25519,
        algorithms,
        founding_authorize_payload_digest: device_authorize_payload_digest(
            &authorize,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap(),
    }
}

/// Deterministic, fully content-bound PCR create Event shared by fixtures that
/// need to name the PCR before seeding its accepted projection.
pub fn fixture_principal_control_realm_create(principal_id: &str) -> arkret_wire::Event {
    let created_at = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
        .expect("fixture PCR genesis timestamp")
        .with_timezone(&chrono::Utc);
    let (principal, principal_full_id) =
        if let Ok(full_id) = DidFullId::new(principal_id.to_owned()) {
            (
                arkret_wire::project_full_id_to_core_id(&full_id)
                    .expect("fixture principal projection"),
                full_id,
            )
        } else {
            let core_id = arkret_identifiers::DidCoreId::new(principal_id.to_owned())
                .expect("fixture PCR principal core id");
            let method_specific = principal_id
                .strip_prefix("ak:did_core:")
                .expect("fixture core id has typed prefix");
            let full_id = DidFullId::new(format!("did:{method_specific}"))
                .expect("fixture principal full id");
            (core_id, full_id)
        };
    arkret_bootstrap::build_self_principal_pcr_create(
        arkret_bootstrap::SelfPrincipalPcrCreateInput {
            principal_id: principal.clone(),
            principal_full_id,
            genesis_salt: arkret_wire::GenesisSalt::new(
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            )
            .expect("fixture PCR genesis salt"),
            trust_domain: arkret_identifiers::TypedTrustDomainId::new(
                "ak:trust_domain:soland.test".to_owned(),
            )
            .expect("fixture PCR trust domain"),
            did_inception_ref: arkret_wire::EventRef::new(
                format!("sha256:{}", "1".repeat(64)),
                arkret_bootstrap::DID_INCEPTION_REF_ROLE,
            ),
            founding_device_descriptor: fixture_pcr_founding_device_descriptor(
                &principal, created_at,
            ),
            capability_action_registry_digest:
                arkret_policy::current_capability_action_registry_digest()
                    .expect("fixture capability action registry digest"),
            created_at,
            hlc: Hlc::new(FIXTURE_BASIS_HLC).expect("fixture PCR genesis HLC"),
        },
        &fixture_registered_projection,
    )
    .expect("fixture closed PCR genesis Event")
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
    _title: &str,
    trust_domain: &str,
    _created_at: chrono::DateTime<chrono::Utc>,
) -> serde_json::Value {
    let controller_organization = arkret_wire::project_full_id_to_core_id(
        &DidFullId::new(subject.to_owned()).expect("fixture controller DID"),
    )
    .expect("fixture controller core id");
    serde_json::json!({
        "object": {
            "schema": "ak.schema.realm_genesis.v1",
            "purpose": "collaboration",
            "genesis_salt": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "reducer_profile": arkret_wire::CORE_REDUCER_PROFILE,
            "trust_domain": trust_domain,
            "schema_refs": ["ak.schema.realm.v1"],
            "encryption_profile": "none",
            "security_class": "standard",
            "notary_profile": "single_did",
            "digest_algorithm": "sha256",
            "capability_action_registry_digest":
                arkret_policy::current_capability_action_registry_digest()
                    .expect("fixture capability action registry digest"),
            "notary": {
                "kind": "single_did",
                "actor_id": notary_did,
                "recovery_members": [FIXTURE_NOTARY_RECOVERY_MEMBER],
                "controller_organization": controller_organization,
                "recovery_controller_organizations": [FIXTURE_NOTARY_RECOVERY_ORGANIZATION]
            }
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
    let realm = arkret_identifiers::RealmId::new(realm_id.to_owned())
        .expect("fixture Realm id is canonical");
    let is_principal_control_realm = realm_id == crate::fixture_principal_control_realm(subject);
    let existing_records = state
        .test_persistence()
        .events()
        .realm_events_newest_first(realm_id)
        .await
        .expect("fixture Realm genesis lookup");
    if let Some(existing) = existing_records
        .iter()
        .find(|record| record.kind == arkret_wire::EventKind::RealmCreate.as_str())
    {
        let event: arkret_wire::Event = serde_json::from_value(existing.envelope.clone())
            .expect("stored fixture genesis envelope");
        let payload = serde_json::to_value(&event.payload).expect("stored fixture genesis payload");
        let has_complete_ordinary_bootstrap = [
            arkret_wire::EventKind::RealmProfile,
            arkret_wire::EventKind::RealmPolicyBundle,
            arkret_wire::EventKind::RealmJoinRule,
            arkret_wire::EventKind::RealmHistoryVisibility,
            arkret_wire::EventKind::RealmDiscovery,
            arkret_wire::EventKind::RealmDeliveryBindingPolicy,
            arkret_wire::EventKind::MemberState,
        ]
        .into_iter()
        .all(|kind| {
            existing_records
                .iter()
                .any(|record| record.kind == kind.as_str())
        });
        if is_principal_control_realm || has_complete_ordinary_bootstrap {
            project_fixture_genesis_event(state, &realm, event, payload).await;
            return;
        }
        let genesis_actor = event.actor_id.to_string();
        persist_and_project_realm_genesis_event(
            state,
            &realm,
            &genesis_actor,
            "Fixture Realm",
            event,
            payload,
        )
        .await;
        return;
    }
    if is_principal_control_realm {
        let event = fixture_principal_control_realm_create(subject);
        let payload = serde_json::to_value(&event.payload).expect("fixture PCR genesis payload");
        project_fixture_genesis_event(state, &realm, event, payload).await;
        return;
    }
    let genesis_event_id = realm.event_id().to_string();
    // A Realm has exactly one canonical create and the store enforces that, so
    // do not write another when this Realm already has one — whether from a
    // previous call here or from a fixture that authored its own genesis
    // Event. The reducer projection is checked separately below: fixtures that
    // write persistence directly still have to materialize the authority root
    // used by authorization predicates.
    let created_at = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
        .expect("fixture genesis timestamp")
        .with_timezone(&chrono::Utc);
    let payload = realm_genesis_payload(
        subject,
        state.service_id(),
        "Fixture Realm",
        "ak:trust_domain:soland.test",
        created_at,
    );
    let event = arkret_wire::test_support::raw_event_at(
        arkret_wire::EventKind::RealmCreate.as_str(),
        arkret_wire::ScopeRef::RealmGenesis,
        arkret_wire::DidCoreId::from(
            arkret_wire::project_full_id_to_core_id(
                &DidFullId::new(subject.to_owned()).expect("fixture genesis actor DID"),
            )
            .expect("fixture genesis actor projection"),
        ),
        0,
        Hlc::new(FIXTURE_BASIS_HLC).expect("fixture genesis HLC"),
        payload.clone(),
        created_at,
    )
    .expect("fixture genesis Event");
    // Event-derived Realms retype their genesis Event token byte-for-byte, so a
    // fixture whose authored Event does not derive this Realm would hand
    // admission a Realm nobody can re-derive.
    assert!(
        event.event_id.to_string() == genesis_event_id,
        "fixture genesis Event {} does not derive Realm {}",
        event.event_id,
        realm
    );
    persist_and_project_realm_genesis_event(
        state,
        &realm,
        subject,
        "Fixture Realm",
        event,
        payload,
    )
    .await;
}

fn fixture_registered_projection(
    event: &arkret_wire::Event,
) -> Result<Vec<arkret_wire::ProjectedCellWrite>, String> {
    arkret_schema::project_registered_cell_writes(event, arkret_canonical::DigestSuite::Sha256)
        .map_err(|error| error.to_string())
}

async fn project_fixture_genesis_event(
    state: &AppState,
    realm: &RealmId,
    event: arkret_wire::Event,
    payload: serde_json::Value,
) {
    let realm_id = realm.as_str();
    if state
        .test_persistence()
        .events()
        .get(event.event_id.as_str())
        .await
        .expect("fixture PCR genesis lookup")
        .is_none()
    {
        state
            .test_persistence()
            .events()
            .put(crate::signed_event::canonical_event_record(
                &event,
                Some(realm_id),
                chrono::Utc::now(),
            ))
            .await
            .expect("fixture PCR genesis Event");
    }

    let projection = state.test_projection();
    let mut projection = projection.lock();
    if projection.realm_genesis_cell_value(realm_id).is_none() {
        let writes = fixture_registered_projection(&event)
            .expect("fixture PCR genesis registered projection");
        let operation = arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(arkret_identifiers::new_prefixed_uuid7(
                "ak:operation:",
            ))
            .expect("fixture PCR genesis Operation id"),
            realm.clone(),
            arkret_wire::EventKind::RealmCreate.as_str(),
            payload,
        );
        let effect = projection.apply_projected(&operation, &writes, state.test_hlc());
        assert!(
            projection.realm_authority_root(realm_id).is_some(),
            "fixture PCR genesis must project its authority root, got {effect:?}"
        );
        assert_eq!(
            projection.realm_digest_algorithm(realm_id).as_deref(),
            Some("sha256"),
            "fixture PCR genesis must project its digest suite; genesis={:?}, effect={effect:?}",
            projection.realm_genesis_cell_value(realm_id),
        );
    }
}

/// Author a canonical genesis Event first and derive its Realm identity from
/// that producer Event. Dynamic Realm fixtures must use this path instead of
/// independently minting an `ak:realm:` token.
pub async fn seed_event_derived_realm_genesis_event(
    state: &AppState,
    subject: &str,
    title: &str,
) -> String {
    let created_at = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
        .expect("fixture genesis timestamp")
        .with_timezone(&chrono::Utc);
    let mut payload = realm_genesis_payload(
        subject,
        state.service_id(),
        title,
        "ak:trust_domain:soland.test",
        created_at,
    );
    payload["object"]["genesis_salt"] = serde_json::json!(
        arkret_wire::GenesisSalt::generate()
            .expect("fixture Realm genesis salt")
            .into_string()
    );
    let event = arkret_wire::test_support::raw_event_at(
        arkret_wire::EventKind::RealmCreate.as_str(),
        arkret_wire::ScopeRef::RealmGenesis,
        arkret_wire::DidCoreId::from(
            arkret_wire::project_full_id_to_core_id(
                &DidFullId::new(subject.to_owned()).expect("fixture genesis actor DID"),
            )
            .expect("fixture genesis actor projection"),
        ),
        0,
        Hlc::new(FIXTURE_BASIS_HLC).expect("fixture genesis HLC"),
        payload.clone(),
        created_at,
    )
    .expect("fixture genesis Event");
    let realm = RealmId::from_event_id(&event.event_id);
    persist_and_project_realm_genesis_event(state, &realm, subject, title, event, payload).await;
    realm.to_string()
}

async fn persist_and_project_realm_genesis_event(
    state: &AppState,
    realm: &RealmId,
    subject: &str,
    profile_title: &str,
    event: arkret_wire::Event,
    payload: serde_json::Value,
) {
    let realm_id = realm.as_str();
    let stored_event_ids = state
        .test_persistence()
        .events()
        .realm_events_newest_first(realm_id)
        .await
        .expect("fixture Realm genesis lookup")
        .iter()
        .map(|record| record.event_id.clone())
        .collect::<std::collections::BTreeSet<_>>();

    let followups = [
        (
            arkret_wire::EventKind::RealmProfile,
            serde_json::json!({"schema": "ak.schema.realm_profile.v1", "title": profile_title}),
        ),
        (
            arkret_wire::EventKind::RealmPolicyBundle,
            serde_json::json!({"policy_revision": 1, "content_scheme": "mls_exporter_aead_v1"}),
        ),
        (
            arkret_wire::EventKind::RealmJoinRule,
            serde_json::json!({"value": "invite"}),
        ),
        (
            arkret_wire::EventKind::RealmHistoryVisibility,
            serde_json::json!({"value": "joined"}),
        ),
        (
            arkret_wire::EventKind::RealmDiscovery,
            serde_json::json!({"value": "invite_only"}),
        ),
        (
            arkret_wire::EventKind::RealmDeliveryBindingPolicy,
            serde_json::json!({"unroutable_membership_allowed": false}),
        ),
        (
            arkret_wire::EventKind::MemberState,
            serde_json::json!({
                "realm_id": realm_id,
                "actor_id": subject,
                "membership": "join",
                "delivery_status": "unroutable"
            }),
        ),
    ];
    let mut bootstrap_events = vec![event.clone()];
    let mut previous_event_id = event.event_id.clone();
    for (offset, (kind, followup_payload)) in followups.into_iter().enumerate() {
        let actor_seq = u64::try_from(offset + 1).expect("fixture bootstrap sequence");
        let mut followup = arkret_wire::test_support::raw_event_at(
            kind.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: realm.clone(),
            },
            arkret_wire::DidCoreId::from(
                arkret_wire::project_full_id_to_core_id(
                    &DidFullId::new(subject.to_owned()).expect("fixture bootstrap actor DID"),
                )
                .expect("fixture bootstrap actor projection"),
            ),
            actor_seq,
            Hlc::new(format!("0196419b0000-{actor_seq:04x}-51c0a1ed"))
                .expect("fixture bootstrap HLC"),
            followup_payload,
            event.created_at,
        )
        .expect("fixture bootstrap follow-up Event");
        followup.prev_refs = vec![previous_event_id];
        followup
            .refresh_content_bound_identity()
            .expect("fixture bootstrap follow-up identity");
        previous_event_id = followup.event_id.clone();
        bootstrap_events.push(followup);
    }
    arkret_policy::realm_bootstrap::validate_realm_bootstrap_unit(&bootstrap_events)
        .expect("fixture ordinary Realm bootstrap unit");

    for bootstrap_event in &bootstrap_events {
        if stored_event_ids.contains(bootstrap_event.event_id.as_str()) {
            continue;
        }
        state
            .test_persistence()
            .events()
            .put(crate::signed_event::canonical_event_record(
                bootstrap_event,
                Some(realm_id),
                chrono::Utc::now(),
            ))
            .await
            .expect("fixture Realm bootstrap Event");
    }

    let projection = state.test_projection();
    let mut projection = projection.lock();
    if projection.realm_authority_root(realm_id).is_none() {
        let writes = arkret_schema::project_registered_cell_writes(
            &event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .expect("fixture genesis registered projection");
        let operation = arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(arkret_identifiers::new_prefixed_uuid7(
                "ak:operation:",
            ))
            .expect("fixture genesis Operation id"),
            realm.clone(),
            arkret_wire::EventKind::RealmCreate.as_str(),
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
                actor_id: arkret_wire::project_full_id_to_core_id(
                    &DidFullId::new(
                        verification_method
                            .split_once('#')
                            .map_or(verification_method, |(did, _)| did)
                            .to_owned(),
                    )
                    .expect("fixture verification method DID"),
                )
                .expect("fixture verification method projection"),
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
            &event.kind,
            arkret_wire::EventKind::RealmCreate | arkret_wire::EventKind::DeviceReanchor
        )
}
