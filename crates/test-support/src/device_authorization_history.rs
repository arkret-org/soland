//! Signed canonical PCR material for device persistence/recovery tests.
//! No helper constructs an opaque verified history without running its verifier.

use std::collections::{BTreeMap, BTreeSet};

use arkret_canonical::DigestSuite;
use arkret_models_collaboration::events_payloads::*;
use arkret_models_identity::ResolutionCommitment;
use arkret_state::{
    CommandEventResult, OrderedControlUnit, OrderedControlUnitEvent, ResolvedCellState,
};
use arkret_wire::*;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;

fn hash(label: &str) -> Hash {
    Hash::new(arkret_canonical::sha256_digest(label.as_bytes())).unwrap()
}
pub fn device(index: u8) -> DeviceId {
    DeviceId::new(format!("ak:device:01904100-0000-7000-8000-{index:012}")).unwrap()
}
fn at() -> DateTime<Utc> {
    "2026-09-12T00:00:00Z".parse().unwrap()
}
fn hlc(sequence: usize) -> Hlc {
    Hlc::new(format!("0198d35d9800-{sequence:04x}-a13f9c2e")).unwrap()
}
fn project(event: &Event) -> std::result::Result<Vec<ProjectedCellWrite>, String> {
    arkret_schema::project_registered_cell_writes(event, DigestSuite::Sha256)
        .map_err(|error| error.to_string())
}
pub fn possession(
    account: &AccountId,
    index: u8,
    binding: DeviceAuthorizationBindingKind,
) -> DeviceAuthorizePayload {
    let key = SigningKey::from_bytes(&[80 + index; 32]);
    let public =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(&key.verifying_key().to_bytes());
    let mut hpke = vec![0xec, 0x01];
    hpke.extend([index; 32]);
    let mut unsigned = UnsignedDeviceAuthorizePayload::new(
        device(index),
        NonEmptyString::new(format!("did:key:{public}")).unwrap(),
        NonEmptyString::new(arkret_canonical::encode_multibase_base58btc(hpke)).unwrap(),
        vec![NonEmptyString::new("ak.hpke_x25519_aead_chacha20poly1305.v1").unwrap()],
        Some(NonEmptyString::new("Ed25519").unwrap()),
        if binding == DeviceAuthorizationBindingKind::AcceptedDevice {
            DeviceOrPrincipalRef::DeviceId(device(1))
        } else {
            DeviceOrPrincipalRef::Principal(account.principal_id.clone())
        },
        None,
        at(),
        None,
        binding,
        (binding == DeviceAuthorizationBindingKind::PcrRecovery).then(|| {
            RecoverySessionId::new("ak:recovery_session:01904100-0000-7000-8000-000000000002")
                .unwrap()
        }),
    )
    .unwrap();
    if binding == DeviceAuthorizationBindingKind::AcceptedDevice {
        unsigned = unsigned.with_pairing_challenge_transcript_digest(hash("pairing"));
    }
    let bytes = unsigned.device_possession_signature_input(account).unwrap();
    unsigned
        .attach_signature(
            Base64UrlString::new(arkret_canonical::base64url_encode(
                key.sign(&bytes).to_bytes(),
            ))
            .unwrap(),
        )
        .unwrap()
}
fn sign_event(mut event: Event, method: DidUrl, seed: [u8; 32]) -> Event {
    event.proofs.clear();
    event
        .refresh_content_bound_identity_with_digest_suite(DigestSuite::Sha256)
        .unwrap();
    let mut proof = ProducerEventProof {
        kind: proof_kind::DETACHED_JWS.into(),
        verification_method: method,
        event_digest: event.event_id.event_digest(),
        signer_resolution_evidence_ref: None,
        created_at: event.created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: String::new(),
    };
    proof.jws = arkret_signatures::jws::sign_jws_ed25519(
        &proof.canonical_binding_bytes(&event.actor_id).unwrap(),
        &SigningKey::from_bytes(&seed),
    )
    .unwrap();
    event.proofs.push(proof);
    event
}
pub struct DeviceHistoryFixture {
    pub account: AccountId,
    pub did: Did,
    pub configuration: NotaryValue,
    pub inception: arkret_models_identity::DidOperationSubmitRequestBody,
    pub events: Vec<Event>,
    pub seals: Vec<Seal>,
    pub state: BTreeMap<CellRef, ResolvedCellState>,
    pub covered: BTreeSet<Hash>,
}
impl DeviceHistoryFixture {
    // Real inception/root/device/Seal signatures and deterministic effects.
    // This fixture does not assert HTTP admission or recovery-session policy.
    pub fn new(station_id: DidCoreId) -> Self {
        let next_root = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            &SigningKey::from_bytes(&[71; 32]).verifying_key().to_bytes(),
        );
        let prepared = arkret_signatures::webvh::prepare_principal_inception(
            &arkret_signatures::webvh::PrincipalInceptionInput {
                provider_endpoint: &"https://principal.example/".parse().unwrap(),
                principal_endpoint: &"https://principal.example/".parse().unwrap(),
                local_id: "alice",
                also_known_as: &[],
                version_time: at(),
                root_seed: &[70; 32],
                next_root_public_key_multibase: &next_root,
                witness_policy: None,
            },
        )
        .unwrap();
        let verified_root =
            arkret_signatures::webvh::validate_principal_inception_operation(&prepared.submit_body)
                .unwrap();
        let did = Did::new(prepared.did.clone()).unwrap();
        let account = AccountId::new(project_did_to_core_id(&did).unwrap(), station_id);
        let payload = possession(
            &account,
            1,
            DeviceAuthorizationBindingKind::RegistrationAnchor,
        );
        let key = SigningKey::from_bytes(&[81; 32]);
        let configuration = NotaryValue::new(
            NotarySignerDescriptor {
                actor_id: ActorId::account(account.clone()),
                verification_method: DidUrl::new(format!("{did}#{}", device(1))).unwrap(),
                key_kind: NotaryKeyKind::Ed25519Raw32,
                jose_algorithm: NotaryJoseAlgorithm::Ed25519,
                frozen_public_key_b64u: arkret_canonical::base64url_encode(
                    key.verifying_key().to_bytes(),
                ),
            },
            0,
        )
        .unwrap();
        let root = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            &SigningKey::from_bytes(&[70; 32]).verifying_key().to_bytes(),
        );
        let mut inception = EventRef::new(
            verified_root.did_version_id.clone(),
            arkret_bootstrap::DID_INCEPTION_REF_ROLE,
        );
        inception.critical = true;
        let create = arkret_bootstrap::build_self_principal_pcr_create(
            arkret_bootstrap::SelfPrincipalPcrCreateInput {
                principal_id: account.principal_id.clone(),
                station_id: account.station_id.clone(),
                principal_did: did.clone(),
                notary: configuration.clone(),
                genesis_salt: GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                    .unwrap(),
                trust_domain: TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
                did_inception_ref: inception,
                initial_resolution: ResolutionCommitment {
                    did: did.clone(),
                    method_history_head: verified_root.log_head_digest.to_string(),
                    version_id: verified_root.did_version_id.clone(),
                },
                founding_device_descriptor: FoundingDeviceDescriptor {
                    descriptor_version: 1,
                    device_id: payload.device_id.clone(),
                    device_public_key_did: payload.device_public_key_did.clone(),
                    device_key_algorithm: FoundingDeviceKeyAlgorithm::Ed25519,
                    device_key_purpose: FoundingDeviceKeyPurpose::EventSigningAndMlsIdentity,
                    hpke_key: payload.hpke_key.clone(),
                    hpke_key_algorithm: FoundingDeviceHpkeKeyAlgorithm::X25519,
                    algorithms: payload.algorithms.clone(),
                    founding_authorize_payload_digest: typed_device_authorize_payload_digest(
                        &payload,
                        DigestSuite::Sha256,
                    )
                    .unwrap(),
                },
                created_at: at(),
                hlc: hlc(0),
            },
            &project,
        )
        .unwrap()
        .into_event();
        let create = sign_event(
            create,
            DidUrl::new(format!("did:key:{root}#{root}")).unwrap(),
            [70; 32],
        );
        let mut fixture = Self {
            account,
            did,
            configuration,
            inception: prepared.submit_body,
            events: Vec::new(),
            seals: Vec::new(),
            state: BTreeMap::new(),
            covered: BTreeSet::new(),
        };
        let mut authorize = fixture.raw_event(
            EventKind::DeviceAuthorize,
            serde_json::to_value(payload).unwrap(),
            &create.realm_id,
            1,
        );
        authorize.prev_refs = vec![create.event_id.clone()];
        authorize = sign_event(
            authorize,
            fixture.configuration.signer.verification_method.clone(),
            [81; 32],
        );
        fixture.append(vec![create, authorize]);
        fixture
    }
    pub fn raw_event(
        &self,
        kind: EventKind,
        payload: serde_json::Value,
        realm: &RealmId,
        sequence: u64,
    ) -> Event {
        let mut event = test_support::raw_event_at(
            kind.as_str(),
            ScopeRef::Realm {
                realm_id: realm.clone(),
            },
            self.account.principal_id.clone(),
            self.account.station_id.clone(),
            sequence,
            hlc(sequence as usize),
            payload,
            at(),
        )
        .unwrap();
        event.seal_basis = self.seals.last().map(|seal| SealBasis {
            leaves: vec![seal.id.clone()],
        });
        event.auth_context = None;
        event.unsigned.clear();
        event
    }
    pub fn event(&self, kind: EventKind, payload: serde_json::Value) -> Event {
        let mut event = self.raw_event(
            kind,
            payload,
            &self.events[0].realm_id,
            self.events.len() as u64,
        );
        event.prev_refs = vec![self.events.last().unwrap().event_id.clone()];
        sign_event(
            event,
            self.configuration.signer.verification_method.clone(),
            [81; 32],
        )
    }
    pub fn append(&mut self, events: Vec<Event>) {
        let registry = arkret_lattice_registry::try_build_sdk_state_registry().unwrap();
        let unit = OrderedControlUnit {
            events: events
                .iter()
                .map(|event| OrderedControlUnitEvent {
                    digest: event.event_id.event_digest(),
                    event: event.clone(),
                    digest_suite: DigestSuite::Sha256,
                })
                .collect(),
        };
        let batch = arkret_state::execute_ordered_control_units(
            &events[0].realm_id,
            &self.state,
            &registry,
            &[unit],
            DigestSuite::Sha256,
            self.seals.is_empty(),
            |member, stage, _| {
                let projection = arkret::project_control_writes_at_state(
                    &member.event,
                    DigestSuite::Sha256,
                    stage,
                )
                .unwrap();
                let effects = projection
                    .writes
                    .iter()
                    .flat_map(|write| {
                        arkret_state::resolve_projected_write(
                            write,
                            &member.event.realm_id,
                            stage,
                            &registry,
                        )
                        .unwrap()
                    })
                    .collect();
                Ok(CommandEventResult::Applied(effects))
            },
        )
        .unwrap();
        self.covered
            .extend(batch.committed_event_digests.iter().cloned());
        let body = UnsignedSeal {
            realm_id: events[0].realm_id.clone(),
            predecessor_ref: self.seals.last().map(|seal| seal.id.clone()),
            delta: batch.committed_event_digests,
            control_event_set_root: arkret_state::control_event_set_root(
                &self.covered,
                DigestSuite::Sha256,
            )
            .unwrap(),
            state_root: arkret_state::compute_state_root(
                arkret_state::GovernanceView::new(&batch.post_state),
                DigestSuite::Sha256,
            )
            .unwrap(),
            notary_seq: self.seals.len() as u64,
            availability_receipt_digests: vec![],
            covered_event_digests: vec![],
            previous_state_root: None,
            previous_digest_algorithm: None,
            sealed_at: at(),
            hlc: hlc(self.seals.len() + 10),
            configuration_ref: self
                .events
                .first()
                .map(|event| event.event_id.clone())
                .unwrap_or_else(|| events[0].event_id.clone()),
            command_results: batch.command_results,
            authorization_closures: vec![],
            existence_anchors: vec![],
        };
        let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
            [81; 32],
            self.did.clone(),
            self.configuration.signer.verification_method.clone(),
        );
        let seal = Seal::sign_with_signer(body, DigestSuite::Sha256, &signer).unwrap();
        self.state = batch.post_state;
        self.seals.push(seal);
        self.events.extend(events);
    }
    pub fn verify(
        &self,
    ) -> std::result::Result<
        arkret::DeviceAuthorizationHistory,
        arkret_state::ordinary_history::HistoryEvidenceError,
    > {
        arkret::DeviceAuthorizationHistory::verify(
            &self.account,
            &self.events[0].event_id,
            &self.configuration,
            &self.inception,
            &self.seals.last().unwrap().id,
            &self.seals,
            &self.events,
            DigestSuite::Sha256,
        )
    }
    pub fn reanchor(&self, null_basis: bool) -> Vec<Event> {
        let payload = possession(
            &self.account,
            3,
            DeviceAuthorizationBindingKind::PcrRecovery,
        );
        let previous = self.seals.last().unwrap();
        let reanchor=self.event(EventKind::DeviceReanchor,json!({
            "account_id":self.account,"recovery_authority_kind":"pcr_policy","recovery_policy_id":"ak:policy:01904100-0000-7000-8000-000000000001",
            "recovery_policy_version":1,"recovery_session_id":"ak:recovery_session:01904100-0000-7000-8000-000000000002",
            "previous_device_generation":1,"new_device_generation":2,
            "pre_fence_seal_frontier":if null_basis {serde_json::Value::Null} else {json!({"leaves":[previous.id],"state_root":previous.state_root,"control_event_set_root":previous.control_event_set_root})},
            "replacement_authorize_payload_digest":typed_device_authorize_payload_digest(&payload,DigestSuite::Sha256).unwrap(),
        }));
        let reanchor = sign_event(
            reanchor,
            DidUrl::new(format!("{}#{}", self.did, device(3))).unwrap(),
            [83; 32],
        );
        let mut authorize = self.event(
            EventKind::DeviceAuthorize,
            serde_json::to_value(payload).unwrap(),
        );
        authorize.actor_seq = reanchor.actor_seq + 1;
        authorize.prev_refs = vec![reanchor.event_id.clone()];
        authorize = sign_event(
            authorize,
            DidUrl::new(format!("{}#{}", self.did, device(3))).unwrap(),
            [83; 32],
        );
        vec![reanchor, authorize]
    }
}
