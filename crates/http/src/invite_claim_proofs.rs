use arkret_event_draft::ProjectedEventOperation as Operation;
#[cfg(test)]
use arkret_identity::DidResolver;
use arkret_models_collaboration::governance::membership_invite::{
    INVITE_CLAIM_AUDIENCE, INVITE_SUBJECT_PROOF_ALG, InviteClaimBindingProof, InviteSubjectProof,
    InviteSubjectProofBody, invite_binding_proof_transcript_bytes,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;
use soland_services::projection::{InviteClaimProofContext, ProjectionService};

use crate::state::AppState;

#[derive(Clone, Debug)]
pub(crate) struct InviteClaimProofVerification<'a> {
    pub invite_id: &'a str,
    pub realm_id: &'a str,
    pub subject_account_id: arkret_wire::AccountId,
    pub token_commitment: &'a str,
    pub claim_nonce: &'a str,
    pub binding_proof: &'a Value,
    pub subject_proof: &'a Value,
    pub expected_verification_public_key: &'a str,
    pub expected_verification_id: &'a str,
    pub invite_digest: &'a str,
}

pub(crate) fn invite_claim_proof_context_from_projection(
    projection: &ProjectionService,
    operation: &Operation,
) -> Result<Option<InviteClaimProofContext>, &'static str> {
    projection.invite_claim_proof_context(operation)
}

pub(crate) async fn verify_invite_claim_proofs_for_operation(
    state: &AppState,
    operation: &Operation,
    context: &InviteClaimProofContext,
) -> Result<(), &'static str> {
    let Some(payload) = operation.payload.as_object() else {
        return Err("invite_claim_payload_not_object");
    };
    let Some(invite_id) = trimmed_string(payload.get("invite_id")) else {
        return Err("invite_id_required");
    };
    let subject_account_id: arkret_wire::AccountId = serde_json::from_value(
        payload
            .get("subject_account_id")
            .cloned()
            .ok_or("subject_account_id_required")?,
    )
    .map_err(|_| "subject_account_id_invalid")?;
    let Some(token_commitment) = trimmed_string(payload.get("token_commitment")) else {
        return Err("token_commitment_required");
    };
    let Some(claim_nonce) = trimmed_string(payload.get("claim_nonce")) else {
        return Err("claim_nonce_required");
    };
    let Some(binding_proof) = payload.get("binding_proof") else {
        return Err("binding_proof_required");
    };
    let Some(subject_proof) = payload.get("subject_proof") else {
        return Err("subject_proof_required");
    };

    let verification = InviteClaimProofVerification {
        invite_id,
        realm_id: operation.realm_id.as_str(),
        subject_account_id,
        token_commitment,
        claim_nonce,
        binding_proof,
        subject_proof,
        expected_verification_public_key: &context.expected_verification_public_key,
        expected_verification_id: &context.expected_verification_id,
        invite_digest: &context.invite_digest,
    };
    verify_invite_claim_proofs_for_state(state, &verification).await
}

#[cfg(test)]
pub(crate) fn verify_invite_claim_proofs(
    resolver: &dyn DidResolver,
    verification: &InviteClaimProofVerification<'_>,
) -> Result<(), &'static str> {
    let binding_service_id = verify_binding_proof_signature(resolver, verification)?;
    verify_subject_proof_signature(resolver, verification, &binding_service_id)
}

async fn verify_invite_claim_proofs_for_state(
    state: &AppState,
    verification: &InviteClaimProofVerification<'_>,
) -> Result<(), &'static str> {
    let binding_service_id = verify_binding_proof_signature_for_state(state, verification).await?;
    verify_subject_proof_signature_for_state(state, verification, &binding_service_id).await
}

#[cfg(test)]
fn verify_binding_proof_signature(
    resolver: &dyn DidResolver,
    verification: &InviteClaimProofVerification<'_>,
) -> Result<String, &'static str> {
    let binding_proof = parse_binding_proof(verification.binding_proof)?;
    let service_id = binding_proof.verification_id.as_str();
    if service_id != verification.expected_verification_id {
        return Err("verification_service_not_authorized");
    }
    let method = binding_proof.verification_method.as_str();
    crate::jws_verify::validate_verification_method_controller(service_id, method)
        .map_err(|_| "binding_proof_method_invalid")?;
    if binding_proof.subject_account_id != verification.subject_account_id {
        return Err("binding_proof_subject_mismatch");
    }
    if binding_proof.realm_id.as_str() != verification.realm_id {
        return Err("binding_proof_realm_mismatch");
    }
    if binding_proof.audience != INVITE_CLAIM_AUDIENCE {
        return Err("binding_proof_audience_mismatch");
    }
    if binding_proof.claim_nonce != verification.claim_nonce {
        return Err("binding_proof_nonce_mismatch");
    }

    let public_key = if verification
        .expected_verification_public_key
        .starts_with("did:")
    {
        if method != verification.expected_verification_public_key {
            return Err("binding_proof_method_mismatch");
        }
        resolve_current_ed25519_key(resolver, service_id, method)
            .map_err(|_| "binding_proof_method_invalid")?
    } else {
        decode_ed25519_multibase_key(verification.expected_verification_public_key)
            .map_err(|_| "binding_proof_public_key_invalid")?
    };

    let signature = decode_signature(Some(binding_proof.signature.as_str()))
        .map_err(|_| "binding_proof_signature_invalid")?;
    let transcript = invite_binding_proof_transcript_bytes(
        &binding_proof,
        verification.invite_id,
        verification.token_commitment,
        verification.invite_digest,
    )
    .map_err(|_| "binding_proof_transcript_invalid")?;
    public_key
        .verify_strict(&transcript, &signature)
        .map_err(|_| "binding_proof_signature_invalid")?;
    Ok(service_id.to_owned())
}

async fn verify_binding_proof_signature_for_state(
    state: &AppState,
    verification: &InviteClaimProofVerification<'_>,
) -> Result<String, &'static str> {
    let binding_proof = parse_binding_proof(verification.binding_proof)?;
    let service_id = binding_proof.verification_id.as_str();
    if service_id != verification.expected_verification_id {
        return Err("verification_service_not_authorized");
    }
    let method = binding_proof.verification_method.as_str();
    crate::jws_verify::validate_verification_method_controller(service_id, method)
        .map_err(|_| "binding_proof_method_invalid")?;
    if binding_proof.subject_account_id != verification.subject_account_id {
        return Err("binding_proof_subject_mismatch");
    }
    if binding_proof.realm_id.as_str() != verification.realm_id {
        return Err("binding_proof_realm_mismatch");
    }
    if binding_proof.audience != INVITE_CLAIM_AUDIENCE {
        return Err("binding_proof_audience_mismatch");
    }
    if binding_proof.claim_nonce != verification.claim_nonce {
        return Err("binding_proof_nonce_mismatch");
    }

    let public_key = if verification
        .expected_verification_public_key
        .starts_with("did:")
    {
        if method != verification.expected_verification_public_key {
            return Err("binding_proof_method_mismatch");
        }
        resolve_current_ed25519_key_for_state(state, service_id, method)
            .await
            .map_err(|_| "binding_proof_method_invalid")?
    } else {
        decode_ed25519_multibase_key(verification.expected_verification_public_key)
            .map_err(|_| "binding_proof_public_key_invalid")?
    };

    let signature = decode_signature(Some(binding_proof.signature.as_str()))
        .map_err(|_| "binding_proof_signature_invalid")?;
    let transcript = invite_binding_proof_transcript_bytes(
        &binding_proof,
        verification.invite_id,
        verification.token_commitment,
        verification.invite_digest,
    )
    .map_err(|_| "binding_proof_transcript_invalid")?;
    public_key
        .verify_strict(&transcript, &signature)
        .map_err(|_| "binding_proof_signature_invalid")?;
    Ok(service_id.to_owned())
}

#[cfg(test)]
fn verify_subject_proof_signature(
    resolver: &dyn DidResolver,
    verification: &InviteClaimProofVerification<'_>,
    binding_service_id: &str,
) -> Result<(), &'static str> {
    if !verification.subject_proof.is_object() {
        return Err("subject_proof_not_object");
    }
    let subject_proof: InviteSubjectProof =
        serde_json::from_value(verification.subject_proof.clone())
            .map_err(|_| "subject_proof_invalid")?;
    if subject_proof.verification_method.trim().is_empty() {
        return Err("subject_proof_method_required");
    }
    if subject_proof.signature_algorithm != INVITE_SUBJECT_PROOF_ALG {
        return Err("subject_proof_alg_unsupported");
    }
    subject_proof
        .validate()
        .map_err(|_| "subject_proof_invalid")?;
    let binding_proof = parse_binding_proof(verification.binding_proof)?;
    let binding_digest = binding_proof
        .canonical_digest()
        .map_err(|_| "binding_proof_digest_invalid")?;
    let transcript_body = InviteSubjectProofBody::from_wire_parts(
        binding_proof.subject_account_id,
        verification.invite_id,
        verification.realm_id,
        verification.token_commitment,
        verification.claim_nonce,
        binding_service_id,
        binding_digest.as_str(),
    )
    .map_err(|_| "subject_proof_transcript_invalid")?;
    let expected_digest = transcript_body
        .transcript_digest()
        .map_err(|_| "subject_proof_transcript_invalid")?;
    if subject_proof.transcript_digest != expected_digest {
        return Err("subject_proof_transcript_mismatch");
    }

    let public_key = resolve_current_ed25519_key(
        resolver,
        verification.subject_account_id.principal_id.as_str(),
        subject_proof.verification_method.as_str(),
    )
    .map_err(|_| "subject_proof_method_not_current")?;
    let signature = decode_signature(Some(subject_proof.signature.as_str()))
        .map_err(|_| "subject_proof_signature_invalid")?;
    let transcript = transcript_body
        .canonical_bytes()
        .map_err(|_| "subject_proof_transcript_invalid")?;
    public_key
        .verify_strict(&transcript, &signature)
        .map_err(|_| "subject_proof_signature_invalid")
}

async fn verify_subject_proof_signature_for_state(
    state: &AppState,
    verification: &InviteClaimProofVerification<'_>,
    binding_service_id: &str,
) -> Result<(), &'static str> {
    if !verification.subject_proof.is_object() {
        return Err("subject_proof_not_object");
    }
    let subject_proof: InviteSubjectProof =
        serde_json::from_value(verification.subject_proof.clone())
            .map_err(|_| "subject_proof_invalid")?;
    if subject_proof.verification_method.trim().is_empty() {
        return Err("subject_proof_method_required");
    }
    if subject_proof.signature_algorithm != INVITE_SUBJECT_PROOF_ALG {
        return Err("subject_proof_alg_unsupported");
    }
    subject_proof
        .validate()
        .map_err(|_| "subject_proof_invalid")?;
    let binding_proof = parse_binding_proof(verification.binding_proof)?;
    let binding_digest = binding_proof
        .canonical_digest()
        .map_err(|_| "binding_proof_digest_invalid")?;
    let transcript_body = InviteSubjectProofBody::from_wire_parts(
        binding_proof.subject_account_id,
        verification.invite_id,
        verification.realm_id,
        verification.token_commitment,
        verification.claim_nonce,
        binding_service_id,
        binding_digest.as_str(),
    )
    .map_err(|_| "subject_proof_transcript_invalid")?;
    let expected_digest = transcript_body
        .transcript_digest()
        .map_err(|_| "subject_proof_transcript_invalid")?;
    if subject_proof.transcript_digest != expected_digest {
        return Err("subject_proof_transcript_mismatch");
    }

    let public_key = resolve_current_ed25519_key_for_state(
        state,
        verification.subject_account_id.principal_id.as_str(),
        subject_proof.verification_method.as_str(),
    )
    .await
    .map_err(|_| "subject_proof_method_not_current")?;
    let signature = decode_signature(Some(subject_proof.signature.as_str()))
        .map_err(|_| "subject_proof_signature_invalid")?;
    let transcript = transcript_body
        .canonical_bytes()
        .map_err(|_| "subject_proof_transcript_invalid")?;
    public_key
        .verify_strict(&transcript, &signature)
        .map_err(|_| "subject_proof_signature_invalid")
}

fn parse_binding_proof(value: &Value) -> Result<InviteClaimBindingProof, &'static str> {
    let proof: InviteClaimBindingProof =
        serde_json::from_value(value.clone()).map_err(|_| "binding_proof_invalid")?;
    proof.validate().map_err(|_| "binding_proof_invalid")?;
    Ok(proof)
}

#[cfg(test)]
fn resolve_current_ed25519_key(
    resolver: &dyn DidResolver,
    controller_id: &str,
    verification_method: &str,
) -> Result<VerifyingKey, String> {
    let controller = verification_method
        .rsplit_once('#')
        .map(|(controller, _)| controller)
        .ok_or_else(|| "verification method has no fragment".to_owned())?;
    let did = arkret_identifiers::Did::new(controller.to_owned())
        .map_err(|error| format!("verification method controller is invalid: {error}"))?;
    let core = arkret_wire::project_did_to_core_id(&did)
        .map_err(|error| format!("verification method controller cannot be projected: {error}"))?;
    if core.as_str() != controller_id {
        return Err("verification method controller does not match core identity".to_owned());
    }
    let document = resolver
        .resolve_did_document(&did)
        .map_err(|error| format!("DID resolution failed: {error}"))?;
    if document.id != did {
        return Err("resolved DID document id does not match requested DID".to_owned());
    }
    crate::jws_verify::require_verification_method_in_document(&document, verification_method)?;
    arkret_identity::jws::resolve_ed25519_pubkey(resolver, verification_method)
        .map_err(|error| error.to_string())
}

async fn resolve_current_ed25519_key_for_state(
    state: &AppState,
    controller_id: &str,
    verification_method: &str,
) -> Result<VerifyingKey, String> {
    let controller = verification_method
        .rsplit_once('#')
        .map(|(controller, _)| controller)
        .ok_or_else(|| "verification method has no fragment".to_owned())?;
    let did = arkret_identifiers::Did::new(controller.to_owned())
        .map_err(|error| format!("verification method controller is invalid: {error}"))?;
    let core = arkret_wire::project_did_to_core_id(&did)
        .map_err(|error| format!("verification method controller cannot be projected: {error}"))?;
    if core.as_str() != controller_id {
        return Err("verification method controller does not match core identity".to_owned());
    }
    let document = crate::jws_verify::resolve_did_document_async(state, &did).await?;
    crate::jws_verify::require_verification_method_in_document(&document, verification_method)?;
    crate::jws_verify::resolve_ed25519_pubkey_async(state, verification_method).await
}

fn decode_ed25519_multibase_key(value: &str) -> Result<VerifyingKey, String> {
    let key = arkret_canonical::decode_ed25519_multibase(value)
        .map_err(|error| format!("verification_public_key is not Ed25519 multibase: {error}"))?;
    VerifyingKey::from_bytes(&key).map_err(|error| format!("Ed25519 key invalid: {error}"))
}

fn decode_signature(value: Option<&str>) -> Result<Signature, String> {
    let value = value.ok_or_else(|| "signature_required".to_owned())?;
    let bytes = URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|error| format!("signature is not base64url: {error}"))?;
    let signature =
        Signature::from_slice(&bytes).map_err(|_| "signature must be 64 bytes".to_owned())?;
    Ok(signature)
}

fn trimmed_string(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use arkret_identifiers::Did;
    use arkret_identity::DidDocument;
    use ed25519_dalek::{Signer as _, SigningKey};
    use serde_json::json;

    use super::*;

    const REALM: &str = "ak:realm:Af9DRPZ6jo28Ku6bsJX3iOs5fu2GLdPa5mI-lkvcujvM";
    const INVITE: &str = "ak:invite:AUftf_3k2fRKMG0NFlHe5iEMBOUpxMwYMRu-yhMJl-yz";
    const SUBJECT: &str = "ak:did_core:web:bob.example";
    const SUBJECT_DID: &str = "did:web:bob.example";
    const SUBJECT_CURRENT_METHOD: &str = "did:web:bob.example#device-current";
    const SUBJECT_OLD_METHOD: &str = "did:web:bob.example#device-old";
    const SERVICE: &str = "ak:did_core:web:verify.example";
    const SERVICE_DID: &str = "did:web:verify.example";
    const SERVICE_METHOD: &str = "did:web:verify.example#invite-key";
    const TOKEN_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const TOKEN_B: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const NONCE: &str = "nonce-claim-proof-1";
    const INVITE_DIGEST: &str =
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    #[derive(Default)]
    struct StubResolver {
        docs: BTreeMap<String, DidDocument>,
    }

    impl StubResolver {
        fn with_method(mut self, did: &str, method: &str, key: &SigningKey) -> Self {
            let document_did = Did::new(did.to_owned()).unwrap();
            let entry = self
                .docs
                .entry(did.to_owned())
                .or_insert_with(|| DidDocument {
                    id: document_did,
                    verification_methods: BTreeMap::new(),
                    also_known_as: Vec::new(),
                    updated_at: Some(chrono::Utc::now()),
                    raw_properties: BTreeMap::new(),
                });
            entry.verification_methods.insert(
                method.to_owned(),
                arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                    key.verifying_key().as_bytes(),
                ),
            );
            self
        }
    }

    impl DidResolver for StubResolver {
        fn supports(&self, did: &Did) -> bool {
            self.docs.contains_key(did.as_str())
        }

        fn resolve_did(&self, did: &Did) -> arkret_identity::Result<arkret_identity::ResolvedDid> {
            self.docs
                .get(did.as_str())
                .cloned()
                .map(arkret_identity::ResolvedDid::proofless)
                .ok_or_else(|| {
                    arkret_identity::IdentityError::Protocol(format!(
                        "stub resolver does not handle {did}"
                    ))
                })
        }
    }

    fn base_verification<'a>(
        binding_proof: &'a Value,
        subject_proof: &'a Value,
    ) -> InviteClaimProofVerification<'a> {
        InviteClaimProofVerification {
            invite_id: INVITE,
            realm_id: REALM,
            subject_account_id: arkret_wire::AccountId::new(
                SUBJECT.parse().unwrap(),
                "ak:did_core:web:subject-station.example".parse().unwrap(),
            ),
            token_commitment: TOKEN_A,
            claim_nonce: NONCE,
            binding_proof,
            subject_proof,
            expected_verification_public_key: SERVICE_METHOD,
            expected_verification_id: SERVICE,
            invite_digest: INVITE_DIGEST,
        }
    }

    fn sign_b64(signing_key: &SigningKey, bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(signing_key.sign(bytes).to_bytes())
    }

    fn signed_binding_proof(
        signing_key: &SigningKey,
        token_commitment: &str,
        invite_id: &str,
        invite_digest: &str,
    ) -> Value {
        let mut binding_proof = json!({
            "verification_id": SERVICE,
            "verification_method": SERVICE_METHOD,
            "subject_account_id": {
                "principal_id": SUBJECT,
                "station_id": "ak:did_core:web:subject-station.example"
            },
            "realm_id": REALM,
            "audience": INVITE_CLAIM_AUDIENCE,
            "claim_nonce": NONCE,
            "expires_at": "2099-01-01T00:00:00.000Z",
            "signature": "placeholder"
        });
        let typed_binding_proof = parse_binding_proof(&binding_proof).unwrap();
        let transcript = invite_binding_proof_transcript_bytes(
            &typed_binding_proof,
            invite_id,
            token_commitment,
            invite_digest,
        )
        .unwrap();
        binding_proof["signature"] = json!(sign_b64(signing_key, &transcript));
        binding_proof
    }

    fn signed_subject_proof(
        signing_key: &SigningKey,
        verification_method: &str,
        binding_proof: &Value,
        token_commitment: &str,
        invite_id: &str,
    ) -> Value {
        let binding_digest = parse_binding_proof(binding_proof)
            .unwrap()
            .canonical_digest()
            .unwrap();
        let transcript_body = InviteSubjectProofBody::from_wire_parts(
            arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new(SUBJECT).unwrap(),
                arkret_wire::DidCoreId::new("ak:did_core:web:subject-station.example").unwrap(),
            ),
            invite_id,
            REALM,
            token_commitment,
            NONCE,
            SERVICE,
            binding_digest.as_str(),
        )
        .unwrap();
        let transcript = transcript_body.canonical_bytes().unwrap();
        serde_json::to_value(InviteSubjectProof::new(
            arkret_wire::DidUrl::new(verification_method).expect("fixture DID URL"),
            transcript_body.transcript_digest().unwrap(),
            sign_b64(signing_key, &transcript),
        ))
        .unwrap()
    }

    #[test]
    fn valid_claim_proofs_verify() {
        let service_key = SigningKey::from_bytes(&[11u8; 32]);
        let subject_key = SigningKey::from_bytes(&[22u8; 32]);
        let resolver = StubResolver::default()
            .with_method(SERVICE_DID, SERVICE_METHOD, &service_key)
            .with_method(SUBJECT_DID, SUBJECT_CURRENT_METHOD, &subject_key);

        let binding_proof = signed_binding_proof(&service_key, TOKEN_A, INVITE, INVITE_DIGEST);
        let subject_proof = signed_subject_proof(
            &subject_key,
            SUBJECT_CURRENT_METHOD,
            &binding_proof,
            TOKEN_A,
            INVITE,
        );
        let verification = base_verification(&binding_proof, &subject_proof);

        verify_invite_claim_proofs(&resolver, &verification).unwrap();
    }

    #[test]
    fn same_principal_at_another_station_cannot_reuse_claim_proofs() {
        let service_key = SigningKey::from_bytes(&[11u8; 32]);
        let subject_key = SigningKey::from_bytes(&[22u8; 32]);
        let resolver = StubResolver::default()
            .with_method(SERVICE_DID, SERVICE_METHOD, &service_key)
            .with_method(SUBJECT_DID, SUBJECT_CURRENT_METHOD, &subject_key);
        let binding_proof = signed_binding_proof(&service_key, TOKEN_A, INVITE, INVITE_DIGEST);
        let subject_proof = signed_subject_proof(
            &subject_key,
            SUBJECT_CURRENT_METHOD,
            &binding_proof,
            TOKEN_A,
            INVITE,
        );
        let mut verification = base_verification(&binding_proof, &subject_proof);
        verification.subject_account_id.station_id =
            "ak:did_core:web:other-station.example".parse().unwrap();
        assert_eq!(
            verify_invite_claim_proofs(&resolver, &verification),
            Err("binding_proof_subject_mismatch")
        );
    }

    #[test]
    fn forged_binding_signature_is_rejected() {
        let service_key = SigningKey::from_bytes(&[11u8; 32]);
        let subject_key = SigningKey::from_bytes(&[22u8; 32]);
        let resolver = StubResolver::default()
            .with_method(SERVICE_DID, SERVICE_METHOD, &service_key)
            .with_method(SUBJECT_DID, SUBJECT_CURRENT_METHOD, &subject_key);

        let mut binding_proof = signed_binding_proof(&service_key, TOKEN_A, INVITE, INVITE_DIGEST);
        binding_proof["signature"] = json!(URL_SAFE_NO_PAD.encode([0u8; 64]));
        let subject_proof = signed_subject_proof(
            &subject_key,
            SUBJECT_CURRENT_METHOD,
            &binding_proof,
            TOKEN_A,
            INVITE,
        );
        let verification = base_verification(&binding_proof, &subject_proof);

        assert_eq!(
            verify_invite_claim_proofs(&resolver, &verification),
            Err("binding_proof_signature_invalid")
        );
    }

    #[test]
    fn old_subject_did_key_is_rejected_even_with_matching_signature() {
        let service_key = SigningKey::from_bytes(&[11u8; 32]);
        let current_subject_key = SigningKey::from_bytes(&[22u8; 32]);
        let old_subject_key = SigningKey::from_bytes(&[33u8; 32]);
        let resolver = StubResolver::default()
            .with_method(SERVICE_DID, SERVICE_METHOD, &service_key)
            .with_method(SUBJECT_DID, SUBJECT_CURRENT_METHOD, &current_subject_key);

        let binding_proof = signed_binding_proof(&service_key, TOKEN_A, INVITE, INVITE_DIGEST);
        let subject_proof = signed_subject_proof(
            &old_subject_key,
            SUBJECT_OLD_METHOD,
            &binding_proof,
            TOKEN_A,
            INVITE,
        );
        let verification = base_verification(&binding_proof, &subject_proof);

        assert_eq!(
            verify_invite_claim_proofs(&resolver, &verification),
            Err("subject_proof_method_not_current")
        );
    }

    #[test]
    fn subject_transcript_replay_across_token_is_rejected() {
        let service_key = SigningKey::from_bytes(&[11u8; 32]);
        let subject_key = SigningKey::from_bytes(&[22u8; 32]);
        let resolver = StubResolver::default()
            .with_method(SERVICE_DID, SERVICE_METHOD, &service_key)
            .with_method(SUBJECT_DID, SUBJECT_CURRENT_METHOD, &subject_key);

        let binding_a = signed_binding_proof(&service_key, TOKEN_A, INVITE, INVITE_DIGEST);
        let subject_a = signed_subject_proof(
            &subject_key,
            SUBJECT_CURRENT_METHOD,
            &binding_a,
            TOKEN_A,
            INVITE,
        );
        let binding_b = signed_binding_proof(&service_key, TOKEN_B, INVITE, INVITE_DIGEST);
        let verification = InviteClaimProofVerification {
            token_commitment: TOKEN_B,
            binding_proof: &binding_b,
            subject_proof: &subject_a,
            ..base_verification(&binding_b, &subject_a)
        };

        assert_eq!(
            verify_invite_claim_proofs(&resolver, &verification),
            Err("subject_proof_transcript_mismatch")
        );
    }

    #[test]
    fn binding_transcript_replay_across_token_is_rejected() {
        let service_key = SigningKey::from_bytes(&[11u8; 32]);
        let subject_key = SigningKey::from_bytes(&[22u8; 32]);
        let resolver = StubResolver::default()
            .with_method(SERVICE_DID, SERVICE_METHOD, &service_key)
            .with_method(SUBJECT_DID, SUBJECT_CURRENT_METHOD, &subject_key);

        let binding_a = signed_binding_proof(&service_key, TOKEN_A, INVITE, INVITE_DIGEST);
        let subject_b = signed_subject_proof(
            &subject_key,
            SUBJECT_CURRENT_METHOD,
            &binding_a,
            TOKEN_B,
            INVITE,
        );
        let verification = InviteClaimProofVerification {
            token_commitment: TOKEN_B,
            binding_proof: &binding_a,
            subject_proof: &subject_b,
            ..base_verification(&binding_a, &subject_b)
        };

        assert_eq!(
            verify_invite_claim_proofs(&resolver, &verification),
            Err("binding_proof_signature_invalid")
        );
    }
}
