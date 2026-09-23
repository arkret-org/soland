//! PCR genesis fixture backed by the formal two-Event/two-Commit authority unit.
//!
//! This builds signed protocol material and a storage transaction. Tests that
//! need an *accepted* PCR must call `admit` and inspect its durable result;
//! constructing the fixture alone makes no authority claim.

use arkret_models_collaboration::events_payloads::device_authorize_payload_digest;
use arkret_models_collaboration::principal_operations::PcrGenesisAdmissionInput;
use arkret_models_identity::{
    IdentityBindingPurpose, IdentityCreationControlProofKind, PCR_GENESIS_UNIT_KINDS,
    UnsignedIdentityCreationControlProof, UnsignedIdentityCreationControlProofBody,
};
use arkret_wire::{
    DidCoreId, Hash, IdempotencyKey, PcrGenesisUnit, RealmCommitAuthorityRef, TrustDomainId,
    WebOrigin,
};
use soland_storage::{
    AuthorityCommitTransaction, CurrentRealmAuthority, PcrGenesisCommitOutcome,
    PcrGenesisCommitUnit, PersistenceResult,
};

use crate::AppStateTestExt as _;
use crate::device_authorization_history::{DeviceHistoryFixture, DeviceHistoryFixtureOptions};

fn hash(value: &str) -> Hash {
    Hash::new(arkret_canonical::sha256_digest(value.as_bytes())).expect("fixture digest")
}

/// Signed PCR material with its exact request body and atomic PG command.
pub struct PcrGenesisFixture {
    pub history: DeviceHistoryFixture,
    pub unit: PcrGenesisCommitUnit,
}

impl PcrGenesisFixture {
    /// Build unique principal history routed through the supplied governance Station.
    #[must_use]
    pub fn new(station: DidCoreId) -> Self {
        let options = DeviceHistoryFixtureOptions {
            local_id: format!("pcr-{}", uuid::Uuid::now_v7().simple()),
            ..Default::default()
        };
        let history = DeviceHistoryFixture::new_with(station.clone(), options);
        let at = history.commits[0].committed_at;
        let evidence = arkret_signatures::webvh::sign_registration_did_evidence_draft(
            &history.inception,
            at,
            &[70; 32],
        )
        .expect("fixture registration DID evidence")
        .accept(at)
        .expect("fixture registration DID evidence acceptance");
        let create = history.events[0].clone();
        let authorize = history.events[1].clone();
        let authorize_value =
            serde_json::Value::Object(authorize.payload.clone().into_iter().collect());
        let create_digest =
            Hash::new(arkret_canonical::canonical_sha256(&create.payload).unwrap()).unwrap();
        let authorize_digest = device_authorize_payload_digest(
            &authorize_value,
            arkret_canonical::DigestSuite::Sha256,
        )
        .expect("fixture authorize payload digest");
        let proof = arkret_signatures::webvh::sign_identity_creation_control_proof(
            UnsignedIdentityCreationControlProof::new(UnsignedIdentityCreationControlProofBody {
                proof_kind: IdentityCreationControlProofKind::DidWebvhInceptionUpdateKey,
                challenge_id: "fixture-challenge".to_owned(),
                challenge: "fixture-challenge-value".to_owned(),
                purpose: IdentityBindingPurpose::AccountBindingAndPcrGenesis,
                account_subject: hash("fixture-account"),
                principal_id: history.account.principal_id.clone(),
                did: history.did.clone(),
                registration_anchor_digest: history
                    .registration_anchor
                    .canonical_digest()
                    .expect("registration anchor digest"),
                did_version_id: evidence.version_id.clone(),
                control_key_digest: evidence.control_key_digest.clone(),
                pcr_realm_id: create.realm_id.clone(),
                realm_create_payload_digest: create_digest,
                founding_authorize_payload_digest: authorize_digest,
                initial_session_request_digest: hash("fixture-initial-session"),
                genesis_unit_kinds: PCR_GENESIS_UNIT_KINDS,
                identity_creation_lease_id: "fixture-lease".to_owned(),
                lease_fence: 1,
                dpop_jkt: "fixture-thumbprint".to_owned(),
                audience_id: station.clone(),
                origin: WebOrigin::new("https://principal.example").unwrap(),
                trust_domain: TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
                issued_at: at,
                expires_at: at + chrono::TimeDelta::minutes(5),
                verification_key_multibase: arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                    &ed25519_dalek::SigningKey::from_bytes(&[70; 32])
                        .verifying_key()
                        .to_bytes(),
                ),
                signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
            })
            .expect("identity creation control proof body"),
            &[70; 32],
        )
        .expect("identity creation control signature");
        let submission = PcrGenesisAdmissionInput {
            account_authority_id: station.clone(),
            principal_id: history.account.principal_id.clone(),
            did: history.did.clone(),
            pcr_realm_id: create.realm_id.clone(),
            did_version_id: evidence.version_id.clone(),
            control_key_digest: evidence.control_key_digest.clone(),
            idempotency_key: IdempotencyKey::new(uuid::Uuid::now_v7().to_string()).unwrap(),
            registration_request_digest: hash("fixture-registration"),
            principal_registration_anchor: history.registration_anchor.clone(),
            registration_did_evidence: evidence,
            identity_creation_control_proof: proof,
            genesis_unit: PcrGenesisUnit::new(create.clone(), authorize.clone())
                .expect("closed PCR genesis unit"),
        };
        let authority = CurrentRealmAuthority {
            realm_id: create.realm_id.clone(),
            generation: 0,
            service_id: station,
            authority_ref: RealmCommitAuthorityRef::GenesisOrChangeEvent(create.event_id.clone()),
            last_handoff_ref: None,
        };
        let transactions = [
            (create, history.commits[0].clone()),
            (authorize, history.commits[1].clone()),
        ]
        .map(|(event, commit)| AuthorityCommitTransaction {
            expected_authority: authority.clone(),
            event,
            commit,
            mls_state: None,
            welcomes: Vec::new(),
            recipient_queue_capacity: 0,
        });
        let exact_request_body =
            serde_json::to_vec(&submission).expect("fixture request body bytes");
        let unit = PcrGenesisCommitUnit {
            submission,
            exact_request_body,
            transactions,
        };
        unit.validate().expect("valid formal PCR genesis unit");
        Self { history, unit }
    }

    /// Submit the unit to the same durable AuthorityCommitStore used in production.
    pub async fn admit(
        &self,
        state: &soland_http::state::AppState,
    ) -> PersistenceResult<PcrGenesisCommitOutcome> {
        state
            .test_persistence()
            .authority_commits()
            .admit_pcr_genesis_unit(&self.unit, self.unit.transactions[0].commit.committed_at)
            .await
    }
}
