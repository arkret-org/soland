//! The caller-signed Event an integration-test fixture submits.
//!
//! Every `durable_effect = event_log` operation now takes the Event from its
//! caller: `capabilities.md` sections 118/361 and `key-management.md` section
//! 411 forbid the service producing that signature. A fixture that exercises one
//! of those surfaces therefore has to author and sign the Move itself, which is
//! more than a request-body change — the envelope owes a CBA basis
//! (`event-auth-state-resolution.md` section 5) and, on a settled CAS register,
//! its own `head_eq` guard.
//!
//! This is the one place that knows how to build that envelope, so the HTTP
//! fixtures and the standalone integration binaries stop each carrying a partial
//! copy of it.

use arkret_identifiers::{Hlc, RealmId, SealId};
use arkret_wire::{DidUrl, Event, EventId, EventInitialSubmission, Precondition, ScopeRef};
use serde_json::Value;

use crate::cba_basis::{FixtureBasis, apply_registered_cba_plane, apply_registered_cba_plane_seal};

/// The Ed25519 seed a fixture actor's device key is derived from.
///
/// The dev-login device fixtures publish the matching public key, so an envelope
/// signed with any other seed fails the device proof rather than a structural
/// check.
pub const FIXTURE_EVENT_SIGNING_SEED: [u8; 32] = [21_u8; 32];

/// Convert an authored SDK Event into the storage representation used by
/// integration fixtures.
///
/// `canonical_bytes` are the Event digest payload, not the serialized signed
/// envelope. Keeping that distinction here prevents fixture records whose
/// content-bound `event_id` cannot be revalidated by the persistence layer.
#[must_use]
pub fn canonical_event_record(
    event: &Event,
    realm_id: Option<&str>,
    received_at: chrono::DateTime<chrono::Utc>,
) -> soland_storage::CanonicalEventRecord {
    soland_storage::CanonicalEventRecord {
        event_id: event.event_id.to_string(),
        actor_id: event.actor_id.to_string(),
        actor_seq: event.actor_seq,
        realm_id: realm_id.map(str::to_owned),
        kind: event.kind.to_string(),
        schema_id: "ak.schema.event.v1".to_owned(),
        digest_suite: arkret_canonical::DigestSuite::Sha256,
        canonical_digest: event
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .expect("fixture Event digest"),
        canonical_bytes: arkret_canonical::canonical_json_bytes(
            &event
                .digest_payload()
                .expect("fixture Event digest payload"),
        )
        .expect("fixture Event canonical digest bytes"),
        envelope: serde_json::to_value(event).expect("fixture Event envelope"),
        received_at,
    }
}

/// Complete an ordinary Realm genesis with the required closed bootstrap
/// facets, preserving one signed actor chain across the whole transaction.
#[must_use]
pub fn complete_realm_bootstrap_unit(
    genesis: Event,
    actor_id: &str,
    device_id: &str,
    profile_title: &str,
) -> Vec<Event> {
    let realm_id = RealmId::from_event_id(&genesis.event_id).to_string();
    let actor_core_id = genesis.actor_id.to_string();
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
                "actor_id": actor_core_id,
                "membership": "join",
                "delivery_status": "unroutable"
            }),
        ),
    ];
    let mut events = vec![genesis];
    for (offset, (kind, payload)) in followups.into_iter().enumerate() {
        let previous_event_id = events
            .last()
            .expect("genesis precedes bootstrap facets")
            .event_id
            .to_string();
        let mut builder =
            CallerSignedEvent::new(kind.as_str(), actor_id, device_id, &realm_id, payload)
                .with_actor_seq(u64::try_from(offset + 1).expect("bootstrap actor sequence"))
                .with_prev_refs(vec![previous_event_id.as_str()])
                .with_basis(CallerSignedBasis::AnchorUnit);
        if kind == arkret_wire::EventKind::MemberState {
            builder = builder.with_preconditions(vec![head_eq_precondition(
                &format!("ak:cell:ak.component.member.state.v1:{actor_core_id}"),
                serde_json::Value::Null,
            )]);
        }
        let event = builder.build();
        events.push(event);
    }
    arkret_policy::realm_bootstrap::validate_realm_bootstrap_unit(&events)
        .expect("fixture ordinary Realm bootstrap unit");
    events
}

/// Where a fixture Event's CBA basis comes from.
#[derive(Clone, Debug)]
pub enum CallerSignedBasis<'a> {
    /// The synthetic genesis unit [`crate::cba_basis`] seals for a Realm that
    /// was stood up straight in `AppState`.
    Fixture(FixtureBasis<'a>),
    /// A Seal this deployment actually accepted, which is what a Realm
    /// bootstrapped through the real `ak.realm.create` batch has to cite.
    AcceptedSeal(SealId),
    /// No CBA field at all: a member of an `event-auth-state-resolution.md`
    /// section 5 anchor unit.
    AnchorUnit,
}

/// A caller-signed Event of any registered kind.
#[derive(Clone, Debug)]
pub struct CallerSignedEvent<'a> {
    kind: &'a str,
    actor_id: &'a str,
    device_id: &'a str,
    realm_id: &'a str,
    actor_seq: u64,
    prev_refs: Vec<&'a str>,
    payload: Value,
    preconditions: Vec<Precondition>,
    basis: CallerSignedBasis<'a>,
    signing_seed: [u8; 32],
    genesis_scope: bool,
}

impl<'a> CallerSignedEvent<'a> {
    /// An Event of `kind` in `realm_id`, signed by `actor_id`'s `device_id` key
    /// and citing this crate's shared fixture basis.
    #[must_use]
    pub fn new(
        kind: &'a str,
        actor_id: &'a str,
        device_id: &'a str,
        realm_id: &'a str,
        payload: Value,
    ) -> Self {
        Self {
            kind,
            actor_id,
            device_id,
            realm_id,
            actor_seq: 0,
            prev_refs: Vec::new(),
            payload,
            preconditions: Vec::new(),
            basis: CallerSignedBasis::Fixture(FixtureBasis::shared(&[])),
            signing_seed: FIXTURE_EVENT_SIGNING_SEED,
            genesis_scope: false,
        }
    }

    /// Author a Realm's genesis `ak.realm.create`.
    ///
    /// `realm-and-space.md` section 2.5.0 gives the create Event the closed
    /// `realm_genesis` scope and derives the Realm id from the Event itself, so
    /// this names no Realm at all — the caller reads the id back with
    /// `RealmId::from_event_id(&event.event_id)` once the Event is built. The
    /// genesis anchor unit also carries no CBA basis field
    /// (`event-auth-state-resolution.md` section 5), and it always opens the
    /// Realm-scoped actor chain at `actor_seq = 0`.
    #[must_use]
    pub fn realm_genesis(actor_id: &'a str, device_id: &'a str, payload: Value) -> Self {
        let mut event = Self::new(
            arkret_wire::EventKind::RealmCreate.as_str(),
            actor_id,
            device_id,
            "",
            payload,
        );
        event.genesis_scope = true;
        event.basis = CallerSignedBasis::AnchorUnit;
        event
    }

    #[must_use]
    pub fn with_actor_seq(mut self, actor_seq: u64) -> Self {
        self.actor_seq = actor_seq;
        self
    }

    #[must_use]
    pub fn with_prev_refs(mut self, prev_refs: Vec<&'a str>) -> Self {
        self.prev_refs = prev_refs;
        self
    }

    /// Attach the guards this Move signs.
    ///
    /// A precondition is inside the signed bytes, so a surface that requires one
    /// can only get it from the caller — refusing an unguarded write is all the
    /// service may still do about it.
    #[must_use]
    pub fn with_preconditions(mut self, preconditions: Vec<Precondition>) -> Self {
        self.preconditions = preconditions;
        self
    }

    #[must_use]
    pub fn with_basis(mut self, basis: CallerSignedBasis<'a>) -> Self {
        self.basis = basis;
        self
    }

    #[must_use]
    pub fn with_fixture_basis(self, basis: FixtureBasis<'a>) -> Self {
        self.with_basis(CallerSignedBasis::Fixture(basis))
    }

    #[must_use]
    pub fn with_accepted_seal_basis(self, seal_id: SealId) -> Self {
        self.with_basis(CallerSignedBasis::AcceptedSeal(seal_id))
    }

    /// The verification method this envelope's proof names.
    #[must_use]
    pub fn verification_method(&self) -> DidUrl {
        fixture_verification_method(self.actor_id, self.device_id)
    }

    /// Build and sign the envelope.
    #[must_use]
    pub fn build(self) -> Event {
        let now = chrono::Utc::now();
        let actor = arkret_identifiers::DidFullId::new(self.actor_id.to_owned())
            .expect("fixture actor DID");
        let actor_id =
            arkret_wire::project_full_id_to_core_id(&actor).expect("fixture actor projection");
        let verification_method = self.verification_method();
        let mut event = arkret_wire::test_support::raw_event_at(
            self.kind,
            if self.genesis_scope {
                ScopeRef::RealmGenesis
            } else {
                ScopeRef::Realm {
                    realm_id: RealmId::new(self.realm_id.to_owned()).expect("fixture Realm id"),
                }
            },
            actor_id,
            crate::fixture_principal_server_id(),
            self.actor_seq,
            Hlc::new(format!(
                "{:012x}-0000-00000000",
                u64::try_from(now.timestamp_millis().max(0)).expect("non-negative epoch millis")
            ))
            .expect("fixture HLC"),
            self.payload,
            now,
        )
        .expect("SDK Event builder accepts the fixture envelope");
        event.prev_refs = self
            .prev_refs
            .into_iter()
            .map(|event_id| EventId::new(event_id.to_owned()).expect("fixture prev_ref"))
            .collect();
        event.preconditions = self.preconditions;
        // v1 carries no producer `effects[]`: the receiver derives every write
        // from `kind + payload` through the registered contract
        // (`event-and-patch.md` section 2.4.2). What a fixture still owes is the
        // CBA envelope shape, which follows from the kind's registered plane.
        match self.basis {
            CallerSignedBasis::Fixture(basis) => {
                apply_registered_cba_plane(&mut event, verification_method.as_str(), basis);
            }
            CallerSignedBasis::AcceptedSeal(seal_id) => {
                apply_registered_cba_plane_seal(&mut event, verification_method.as_str(), seal_id);
            }
            CallerSignedBasis::AnchorUnit => {}
        }
        let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
            self.signing_seed,
            actor,
            verification_method.clone(),
        );
        // Producer-signed content is complete: derive the identity once, then
        // attach the proof the same way a real client does.
        let mut event = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
            event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .expect("the fixture envelope finalizes");
        arkret_signatures::sign_event(
            &mut event,
            &signer,
            &verification_method,
            arkret_signatures::SignEventOptions::new().with_created_at(now),
        )
        .expect("SDK Event signer accepts the fixture envelope");
        event.into_event()
    }

    /// Build and sign the envelope, as the JSON an HTTP fixture posts.
    #[must_use]
    pub fn build_value(self) -> Value {
        serde_json::to_value(self.build()).expect("SDK Event serializes")
    }

    /// Build and sign the envelope, wrapped the way the caller-signed request
    /// bodies carry it.
    #[must_use]
    pub fn build_submission(self) -> EventInitialSubmission {
        EventInitialSubmission::online(self.build())
    }
}

/// The `head_eq` guard naming the complete settled value a Control Move
/// replaces.
///
/// The service used to read the settled value and attach this itself. It cannot
/// any more — the precondition is inside the bytes the caller signs — so a
/// fixture for one of those surfaces reads the cell first, exactly like the real
/// caller now has to.
#[must_use]
pub fn head_eq_precondition(cell: &str, settled_value: Value) -> Precondition {
    serde_json::from_value(serde_json::json!({
        "cell": cell,
        "predicate": { "op": "head_eq", "value": settled_value },
    }))
    .expect("fixture head_eq precondition")
}

/// The DID URL a fixture actor's device key is published under.
#[must_use]
pub fn fixture_verification_method(actor_id: &str, device_id: &str) -> DidUrl {
    let device_id = if device_id.starts_with("ak:device:") {
        device_id.to_owned()
    } else {
        format!("ak:device:{device_id}")
    };
    DidUrl::new(format!("{actor_id}#{device_id}"))
        .expect("fixture verification method is a DID URL")
}
