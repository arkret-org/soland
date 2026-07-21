use serde_json::{Value, json};

use super::*;

const REALM: &str = "ak:realm:0196419b-0000-7000-8000-000000000001";
const INVITE: &str = "ak:invite:0196419b-0000-7000-8000-000000000101";
const INVITER: &str = "did:web:alice.example";
const SUBJECT: &str = "did:web:bob.example";
const SUBJECT_METHOD: &str = "did:web:bob.example#device-1";
const SERVICE: &str = "did:web:verify.example";
const VERIFICATION_METHOD: &str = "did:web:verify.example#invite-key";
const TOKEN_COMMITMENT: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn third_party_invite(expires_at: &str) -> Value {
    json!({
        "invite": {
            "id": INVITE,
            "schema": "ak.schema.invite.v1",
            "realm_id": REALM,
            "inviter": INVITER,
            "join_rule_snapshot": {
                "join_rule": "invite",
                "role": "member"
            },
            "state": "pending",
            "expires_at": expires_at,
            "created_at": "2026-01-01T00:00:00.000Z",
            "third_party_id": {
                "oob_code_kind": "offline_token",
                "token_commitment": TOKEN_COMMITMENT,
                "token_salt_id": "salt-1",
                "token_entropy_bits": 128,
                "verification_service_id": SERVICE,
                "verification_public_key": VERIFICATION_METHOD,
                "max_claims": 1
            }
        }
    })
}

fn claim_payload(nonce: &str, token_commitment: &str, service_id: &str) -> Value {
    let binding_proof = json!({
        "verification_service_id": service_id,
        "verification_method": VERIFICATION_METHOD,
        "subject_id": SUBJECT,
        "realm_id": REALM,
        "audience": "arkret.invite.claim",
        "claim_nonce": nonce,
        "expires_at": "2099-01-01T00:00:00.000Z",
        "signature": "test-signature"
    });
    let binding_digest = arkret_core::canonical::canonical_sha256(&binding_proof).unwrap();
    let transcript_digest = arkret_core::invite_subject_proof_transcript_digest(
        SUBJECT,
        INVITE,
        REALM,
        token_commitment,
        nonce,
        service_id,
        binding_digest.as_str(),
    )
    .unwrap();
    json!({
        "invite_id": INVITE,
        "subject_id": SUBJECT,
        "token_commitment": token_commitment,
        "claim_nonce": nonce,
        "binding_proof": binding_proof,
        "subject_proof": {
            "verification_method": SUBJECT_METHOD,
            "alg": "EdDSA",
            "transcript_digest": transcript_digest,
            "signature": "subject-signature"
        }
    })
}

fn seed_invite(state: &mut ProjectionState, hlc: &ServerHlc, expires_at: &str) {
    let effect = state.apply(
        &make_operation(
            arkret_core::events::EventKind::INVITE_THIRD_PARTY,
            REALM,
            third_party_invite(expires_at),
        ),
        hlc,
    );
    assert!(matches!(
        effect,
        ProjectionEffect::InviteStateChanged { ref state, .. } if state == "pending"
    ));
}

fn seed_realm_policy_allowlist(state: &mut ProjectionState, hlc: &ServerHlc, services: Vec<&str>) {
    let effect = state.apply(
        &make_operation(
            arkret_core::events::EventKind::REALM_POLICY_COMPONENTS,
            REALM,
            json!({
                "third_party_invite_verification_services": services
            }),
        ),
        hlc,
    );
    assert!(matches!(
        effect,
        ProjectionEffect::RealmPolicyComponentsProjected { .. }
    ));
}

#[test]
fn invite_claim_converts_third_party_invite_to_claimed_invite() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("invite-claim");
    seed_invite(&mut state, &hlc, "2099-01-01T00:00:00.000Z");
    seed_realm_policy_allowlist(&mut state, &hlc, vec![SERVICE]);

    let effect = state.apply(
        &make_operation(
            arkret_core::events::EventKind::INVITE_CLAIM,
            REALM,
            claim_payload("nonce-0000000001", TOKEN_COMMITMENT, SERVICE),
        ),
        &hlc,
    );

    assert!(matches!(
        effect,
        ProjectionEffect::InviteStateChanged {
            ref invite_id,
            ref state,
            ref invitee,
            ..
        } if invite_id == INVITE && state == "claimed" && invitee.as_deref() == Some(SUBJECT)
    ));
    let invite = state.invites.get(INVITE).expect("invite projected");
    assert_eq!(invite.state, "claimed");
    assert_eq!(invite.invitee.as_deref(), Some(SUBJECT));
    assert!(
        invite
            .claim_nonces
            .get("nonce-0000000001")
            .is_some_and(|operation_id| operation_id.starts_with("ak:operation:"))
    );
    let third_party_id = invite.third_party_id.as_ref().expect("third_party_id");
    assert_eq!(
        third_party_id
            .get("token_commitment")
            .and_then(Value::as_str),
        Some(TOKEN_COMMITMENT)
    );
    assert!(third_party_id.get("token_salt_id").is_none());
    let member = state
        .member(REALM, SUBJECT)
        .expect("claimed subject should have an invite membership proposal");
    assert_eq!(member.state, "invite");
}

#[test]
fn invite_claim_rejects_reused_claim_nonce() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("invite-claim-nonce");
    seed_invite(&mut state, &hlc, "2099-01-01T00:00:00.000Z");
    seed_realm_policy_allowlist(&mut state, &hlc, vec![SERVICE]);

    assert!(!matches!(
        state.apply(
            &make_operation(
                arkret_core::events::EventKind::INVITE_CLAIM,
                REALM,
                claim_payload("nonce-0000000001", TOKEN_COMMITMENT, SERVICE),
            ),
            &hlc,
        ),
        ProjectionEffect::Rejected { .. }
    ));

    let replay = state.apply(
        &make_operation(
            arkret_core::events::EventKind::INVITE_CLAIM,
            REALM,
            claim_payload("nonce-0000000001", TOKEN_COMMITMENT, SERVICE),
        ),
        &hlc,
    );
    assert!(matches!(
        replay,
        ProjectionEffect::Rejected { ref reason } if reason == "duplicate_conflict"
    ));
}

#[test]
fn invite_claim_records_nonce_before_rejecting_bad_commitment() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("invite-claim-commitment");
    seed_invite(&mut state, &hlc, "2099-01-01T00:00:00.000Z");

    let rejected = state.apply(
        &make_operation(
            arkret_core::events::EventKind::INVITE_CLAIM,
            REALM,
            claim_payload(
                "nonce-bad-commitment",
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                SERVICE,
            ),
        ),
        &hlc,
    );
    assert!(matches!(
        rejected,
        ProjectionEffect::Rejected { ref reason } if reason == "not_found"
    ));
    let invite = state.invites.get(INVITE).expect("invite projected");
    assert_eq!(invite.state, "pending");
    assert!(invite.claim_nonces.contains_key("nonce-bad-commitment"));
}

#[test]
fn invite_claim_rechecks_verification_service_authorization() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("invite-claim-allowlist");
    seed_invite(&mut state, &hlc, "2099-01-01T00:00:00.000Z");
    seed_realm_policy_allowlist(&mut state, &hlc, vec![SERVICE]);

    let rejected = state.apply(
        &make_operation(
            arkret_core::events::EventKind::INVITE_CLAIM,
            REALM,
            claim_payload(
                "nonce-service-0001",
                TOKEN_COMMITMENT,
                "did:web:other.example",
            ),
        ),
        &hlc,
    );
    assert!(matches!(
        rejected,
        ProjectionEffect::Rejected { ref reason } if reason == "verification_service_not_authorized"
    ));
}

#[test]
fn invite_claim_rejects_invite_bound_service_without_current_policy_allowlist() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("invite-claim-policy-dropped");
    seed_invite(&mut state, &hlc, "2099-01-01T00:00:00.000Z");

    let rejected = state.apply(
        &make_operation(
            arkret_core::events::EventKind::INVITE_CLAIM,
            REALM,
            claim_payload("nonce-no-policy-01", TOKEN_COMMITMENT, SERVICE),
        ),
        &hlc,
    );
    assert!(matches!(
        rejected,
        ProjectionEffect::Rejected { ref reason } if reason == "verification_service_not_authorized"
    ));
    assert!(
        state.member(REALM, SUBJECT).is_none(),
        "missing current Realm allowlist must not create membership proposal"
    );
}

#[test]
fn invite_claim_rejects_when_current_policy_no_longer_allows_bound_service() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("invite-claim-policy-rotated");
    seed_invite(&mut state, &hlc, "2099-01-01T00:00:00.000Z");
    seed_realm_policy_allowlist(&mut state, &hlc, vec!["did:web:other.example"]);

    let rejected = state.apply(
        &make_operation(
            arkret_core::events::EventKind::INVITE_CLAIM,
            REALM,
            claim_payload("nonce-policy-rotated", TOKEN_COMMITMENT, SERVICE),
        ),
        &hlc,
    );
    assert!(matches!(
        rejected,
        ProjectionEffect::Rejected { ref reason } if reason == "verification_service_not_authorized"
    ));
}

#[test]
fn expired_invite_claim_cleans_active_token_material() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("invite-claim-expiry");
    let effect = state.apply(
        &make_operation(
            arkret_core::events::EventKind::INVITE_THIRD_PARTY,
            REALM,
            third_party_invite("2000-01-01T00:00:00.000Z"),
        ),
        &hlc,
    );
    assert!(matches!(
        effect,
        ProjectionEffect::InviteStateChanged { ref state, .. } if state == "expired"
    ));
    let invite = state.invites.get(INVITE).expect("invite projected");
    let third_party_id = invite.third_party_id.as_ref().expect("third_party_id");
    assert!(third_party_id.get("token_commitment").is_none());
    assert!(third_party_id.get("token_salt_id").is_none());

    let rejected = state.apply(
        &make_operation(
            arkret_core::events::EventKind::INVITE_CLAIM,
            REALM,
            claim_payload("nonce-expired-001", TOKEN_COMMITMENT, SERVICE),
        ),
        &hlc,
    );
    assert!(matches!(
        rejected,
        ProjectionEffect::Rejected { ref reason } if reason == "expired_invite_token"
    ));
}
