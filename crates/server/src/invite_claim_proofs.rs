use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::SecondsFormat;
use cokret_sdk::identity::DidResolver;
use cokret_sdk::{Did, Operation, canonical};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{Value, json};

use crate::reducer::{InviteProjection, ProjectionState};
use crate::state::AppState;

const INVITE_AUDIENCE: &str = "cokret.invite.claim";
const SUBJECT_PROOF_TRANSCRIPT_DOMAIN: &str = "ck.invite.claim.subject_proof.v1\n";
const BINDING_PROOF_TRANSCRIPT_DOMAIN: &str = "ck.invite.claim.binding_proof.v1\n";

#[derive(Clone, Debug)]
pub(crate) struct InviteClaimProofContext {
    expected_verification_public_key: String,
    expected_verification_service_did: String,
    invite_digest: String,
}

#[derive(Clone, Debug)]
pub(crate) struct InviteClaimProofVerification<'a> {
    pub invite_id: &'a str,
    pub realm_id: &'a str,
    pub subject_id: &'a str,
    pub token_commitment: &'a str,
    pub claim_nonce: &'a str,
    pub binding_proof: &'a Value,
    pub subject_proof: &'a Value,
    pub expected_verification_public_key: &'a str,
    pub expected_verification_service_did: &'a str,
    pub invite_digest: &'a str,
}

pub(crate) fn invite_claim_proof_context_from_projection(
    projection: &ProjectionState,
    operation: &Operation,
) -> Result<Option<InviteClaimProofContext>, &'static str> {
    if !crate::kinds::operation_is_invite_claim(operation) {
        return Ok(None);
    }
    let Some(payload) = operation.payload.as_object() else {
        return Err("invite_claim_payload_not_object");
    };
    let Some(invite_id) = trimmed_string(payload.get("invite_id")) else {
        return Err("invite_id_required");
    };
    let Some(invite) = projection.invites.get(invite_id) else {
        return Err("not_found");
    };
    let Some(third_party_id) = invite.third_party_id.as_ref() else {
        return Err("not_found");
    };
    let Some(expected_verification_public_key) =
        trimmed_string(third_party_id.get("verification_public_key"))
    else {
        return Err("verification_public_key_required");
    };
    let Some(expected_verification_service_did) =
        trimmed_string(third_party_id.get("verification_service_did"))
    else {
        return Err("verification_service_did_required");
    };
    let invite_digest = invite_record_digest(invite, third_party_id)?;
    Ok(Some(InviteClaimProofContext {
        expected_verification_public_key: expected_verification_public_key.to_owned(),
        expected_verification_service_did: expected_verification_service_did.to_owned(),
        invite_digest,
    }))
}

pub(crate) fn verify_invite_claim_proofs_for_operation(
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
    let Some(subject_id) = trimmed_string(payload.get("subject_id")) else {
        return Err("subject_id_required");
    };
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
        subject_id,
        token_commitment,
        claim_nonce,
        binding_proof,
        subject_proof,
        expected_verification_public_key: &context.expected_verification_public_key,
        expected_verification_service_did: &context.expected_verification_service_did,
        invite_digest: &context.invite_digest,
    };
    verify_invite_claim_proofs(&*state.did_resolver as &dyn DidResolver, &verification)
}

pub(crate) fn verify_invite_claim_proofs(
    resolver: &dyn DidResolver,
    verification: &InviteClaimProofVerification<'_>,
) -> Result<(), &'static str> {
    let binding_service_did = verify_binding_proof_signature(resolver, verification)?;
    verify_subject_proof_signature(resolver, verification, binding_service_did)
}

pub(crate) fn subject_proof_transcript_digest(
    subject_id: &str,
    invite_id: &str,
    realm_id: &str,
    token_commitment: &str,
    claim_nonce: &str,
    verification_service_did: &str,
    binding_proof_digest: &str,
) -> Result<String, String> {
    let bytes = subject_proof_transcript_bytes(
        subject_id,
        invite_id,
        realm_id,
        token_commitment,
        claim_nonce,
        verification_service_did,
        binding_proof_digest,
    )?;
    Ok(canonical::sha256_digest(bytes))
}

pub(crate) fn subject_proof_transcript_bytes(
    subject_id: &str,
    invite_id: &str,
    realm_id: &str,
    token_commitment: &str,
    claim_nonce: &str,
    verification_service_did: &str,
    binding_proof_digest: &str,
) -> Result<Vec<u8>, String> {
    let transcript = json!({
        "audience": INVITE_AUDIENCE,
        "binding_proof_digest": binding_proof_digest,
        "claim_nonce": claim_nonce,
        "invite_id": invite_id,
        "realm_id": realm_id,
        "subject_id": subject_id,
        "token_commitment": token_commitment,
        "verification_service_did": verification_service_did,
    });
    transcript_bytes(SUBJECT_PROOF_TRANSCRIPT_DOMAIN, &transcript)
}

fn verify_binding_proof_signature<'a>(
    resolver: &dyn DidResolver,
    verification: &'a InviteClaimProofVerification<'a>,
) -> Result<&'a str, &'static str> {
    let object = verification
        .binding_proof
        .as_object()
        .ok_or("binding_proof_not_object")?;
    let service_did = proof_string(object, "verification_service_did")
        .ok_or("binding_proof_service_did_required")?;
    if service_did != verification.expected_verification_service_did {
        return Err("verification_service_not_authorized");
    }
    let method =
        proof_string(object, "verification_method").ok_or("binding_proof_method_required")?;
    crate::jws_verify::validate_verification_method_controller(service_did, method)
        .map_err(|_| "binding_proof_method_invalid")?;
    if proof_string(object, "subject_id") != Some(verification.subject_id) {
        return Err("binding_proof_subject_mismatch");
    }
    if proof_string(object, "realm_id") != Some(verification.realm_id) {
        return Err("binding_proof_realm_mismatch");
    }
    if proof_string(object, "audience") != Some(INVITE_AUDIENCE) {
        return Err("binding_proof_audience_mismatch");
    }
    if proof_string(object, "claim_nonce") != Some(verification.claim_nonce) {
        return Err("binding_proof_nonce_mismatch");
    }

    let public_key = if verification
        .expected_verification_public_key
        .starts_with("did:")
    {
        if method != verification.expected_verification_public_key {
            return Err("binding_proof_method_mismatch");
        }
        resolve_current_ed25519_key(resolver, service_did, method)
            .map_err(|_| "binding_proof_method_invalid")?
    } else {
        decode_ed25519_multibase_key(verification.expected_verification_public_key)
            .map_err(|_| "binding_proof_public_key_invalid")?
    };

    let signature =
        decode_signature(proof_string(object, "signature").or_else(|| proof_string(object, "sig")))
            .map_err(|_| "binding_proof_signature_invalid")?;
    let transcript = binding_proof_transcript_bytes(verification)
        .map_err(|_| "binding_proof_transcript_invalid")?;
    public_key
        .verify_strict(&transcript, &signature)
        .map_err(|_| "binding_proof_signature_invalid")?;
    Ok(service_did)
}

fn verify_subject_proof_signature(
    resolver: &dyn DidResolver,
    verification: &InviteClaimProofVerification<'_>,
    binding_service_did: &str,
) -> Result<(), &'static str> {
    let object = verification
        .subject_proof
        .as_object()
        .ok_or("subject_proof_not_object")?;
    let method =
        proof_string(object, "verification_method").ok_or("subject_proof_method_required")?;
    if object.get("alg").and_then(Value::as_str) != Some("EdDSA") {
        return Err("subject_proof_alg_unsupported");
    }
    let Some(transcript_digest) = proof_string(object, "transcript_digest") else {
        return Err("subject_proof_transcript_required");
    };
    let binding_digest = canonical::canonical_sha256(verification.binding_proof)
        .map_err(|_| "binding_proof_digest_invalid")?;
    let transcript = subject_proof_transcript_bytes(
        verification.subject_id,
        verification.invite_id,
        verification.realm_id,
        verification.token_commitment,
        verification.claim_nonce,
        binding_service_did,
        &binding_digest,
    )
    .map_err(|_| "subject_proof_transcript_invalid")?;
    let expected_digest = canonical::sha256_digest(&transcript);
    if transcript_digest != expected_digest {
        return Err("subject_proof_transcript_mismatch");
    }

    let public_key = resolve_current_ed25519_key(resolver, verification.subject_id, method)
        .map_err(|_| "subject_proof_method_not_current")?;
    let signature = decode_signature(proof_string(object, "signature"))
        .map_err(|_| "subject_proof_signature_invalid")?;
    public_key
        .verify_strict(&transcript, &signature)
        .map_err(|_| "subject_proof_signature_invalid")
}

fn binding_proof_transcript_bytes(
    verification: &InviteClaimProofVerification<'_>,
) -> Result<Vec<u8>, String> {
    let binding_proof = unsigned_binding_proof(verification.binding_proof)?;
    let transcript = json!({
        "audience": INVITE_AUDIENCE,
        "binding_proof": binding_proof,
        "claim_nonce": verification.claim_nonce,
        "invite_digest": verification.invite_digest,
        "invite_id": verification.invite_id,
        "realm_id": verification.realm_id,
        "subject_id": verification.subject_id,
        "token_commitment": verification.token_commitment,
        "verification_service_did": verification.expected_verification_service_did,
    });
    transcript_bytes(BINDING_PROOF_TRANSCRIPT_DOMAIN, &transcript)
}

fn unsigned_binding_proof(binding_proof: &Value) -> Result<Value, String> {
    let Some(object) = binding_proof.as_object() else {
        return Err("binding_proof_not_object".to_owned());
    };
    let mut unsigned = object.clone();
    unsigned.remove("signature");
    unsigned.remove("sig");
    if unsigned.len() == object.len() {
        return Err("binding_proof_signature_required".to_owned());
    }
    Ok(Value::Object(unsigned))
}

fn transcript_bytes(domain: &str, transcript: &Value) -> Result<Vec<u8>, String> {
    let mut bytes = domain.as_bytes().to_vec();
    bytes.extend(
        canonical::canonical_json_bytes(transcript)
            .map_err(|error| format!("canonical transcript failed: {error}"))?,
    );
    Ok(bytes)
}

fn invite_record_digest(
    invite: &InviteProjection,
    third_party_id: &Value,
) -> Result<String, &'static str> {
    let invite_record = json!({
        "expires_at": invite.expires_at.to_rfc3339_opts(SecondsFormat::Secs, true),
        "invite_id": invite.invite_id,
        "realm_id": invite.realm_id,
        "third_party_id": third_party_id,
    });
    canonical::canonical_sha256(&invite_record).map_err(|_| "invite_digest_invalid")
}

fn resolve_current_ed25519_key(
    resolver: &dyn DidResolver,
    controller_did: &str,
    verification_method: &str,
) -> Result<VerifyingKey, String> {
    crate::jws_verify::validate_verification_method_controller(
        controller_did,
        verification_method,
    )?;
    let did = Did::new(controller_did.to_owned())
        .map_err(|error| format!("controller DID invalid: {error}"))?;
    let document = resolver
        .resolve_did(&did)
        .map_err(|error| format!("DID resolution failed: {error}"))?;
    if document.id != did {
        return Err("resolved DID document id does not match requested DID".to_owned());
    }
    crate::jws_verify::require_verification_method_in_document(&document, verification_method)?;
    cokret_sdk::jws::resolve_ed25519_pubkey(resolver, verification_method)
}

fn decode_ed25519_multibase_key(value: &str) -> Result<VerifyingKey, String> {
    let key = cokret_sdk::decode_ed25519_multibase(value)
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

fn proof_string<'a>(object: &'a serde_json::Map<String, Value>, field: &str) -> Option<&'a str> {
    trimmed_string(object.get(field))
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

    use base64::Engine as _;
    use cokret_sdk::identity::DidDocument;
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;

    const REALM: &str = "ck:realm:0196419b-0000-7000-8000-000000000001";
    const INVITE: &str = "ck:invite:0196419b-0000-7000-8000-000000000101";
    const SUBJECT: &str = "did:web:bob.example";
    const SUBJECT_CURRENT_METHOD: &str = "did:web:bob.example#device-current";
    const SUBJECT_OLD_METHOD: &str = "did:web:bob.example#device-old";
    const SERVICE: &str = "did:web:verify.example";
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
                    updated_at: chrono::Utc::now(),
                });
            entry.verification_methods.insert(
                method.to_owned(),
                cokret_sdk::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes()),
            );
            self
        }
    }

    impl DidResolver for StubResolver {
        fn supports(&self, did: &Did) -> bool {
            self.docs.contains_key(did.as_str())
        }

        fn resolve_did(&self, did: &Did) -> cokret_sdk::Result<DidDocument> {
            self.docs.get(did.as_str()).cloned().ok_or_else(|| {
                cokret_sdk::Error::Protocol(format!("stub resolver does not handle {did}"))
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
            subject_id: SUBJECT,
            token_commitment: TOKEN_A,
            claim_nonce: NONCE,
            binding_proof,
            subject_proof,
            expected_verification_public_key: SERVICE_METHOD,
            expected_verification_service_did: SERVICE,
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
            "verification_service_did": SERVICE,
            "verification_method": SERVICE_METHOD,
            "subject_id": SUBJECT,
            "realm_id": REALM,
            "audience": INVITE_AUDIENCE,
            "claim_nonce": NONCE,
            "expires_at": "2099-01-01T00:00:00Z",
            "signature": "placeholder"
        });
        let subject_placeholder = json!({"signature": "placeholder"});
        let verification = InviteClaimProofVerification {
            invite_id,
            realm_id: REALM,
            subject_id: SUBJECT,
            token_commitment,
            claim_nonce: NONCE,
            binding_proof: &binding_proof,
            subject_proof: &subject_placeholder,
            expected_verification_public_key: SERVICE_METHOD,
            expected_verification_service_did: SERVICE,
            invite_digest,
        };
        let transcript = binding_proof_transcript_bytes(&verification).unwrap();
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
        let binding_digest = canonical::canonical_sha256(binding_proof).unwrap();
        let transcript = subject_proof_transcript_bytes(
            SUBJECT,
            invite_id,
            REALM,
            token_commitment,
            NONCE,
            SERVICE,
            &binding_digest,
        )
        .unwrap();
        json!({
            "verification_method": verification_method,
            "alg": "EdDSA",
            "transcript_digest": canonical::sha256_digest(&transcript),
            "signature": sign_b64(signing_key, &transcript)
        })
    }

    #[test]
    fn valid_claim_proofs_verify() {
        let service_key = SigningKey::from_bytes(&[11u8; 32]);
        let subject_key = SigningKey::from_bytes(&[22u8; 32]);
        let resolver = StubResolver::default()
            .with_method(SERVICE, SERVICE_METHOD, &service_key)
            .with_method(SUBJECT, SUBJECT_CURRENT_METHOD, &subject_key);

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
    fn forged_binding_signature_is_rejected() {
        let service_key = SigningKey::from_bytes(&[11u8; 32]);
        let subject_key = SigningKey::from_bytes(&[22u8; 32]);
        let resolver = StubResolver::default()
            .with_method(SERVICE, SERVICE_METHOD, &service_key)
            .with_method(SUBJECT, SUBJECT_CURRENT_METHOD, &subject_key);

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
            .with_method(SERVICE, SERVICE_METHOD, &service_key)
            .with_method(SUBJECT, SUBJECT_CURRENT_METHOD, &current_subject_key);

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
            .with_method(SERVICE, SERVICE_METHOD, &service_key)
            .with_method(SUBJECT, SUBJECT_CURRENT_METHOD, &subject_key);

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
            .with_method(SERVICE, SERVICE_METHOD, &service_key)
            .with_method(SUBJECT, SUBJECT_CURRENT_METHOD, &subject_key);

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
