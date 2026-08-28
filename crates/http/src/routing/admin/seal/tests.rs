use serde_json::{Value, json};
use soland_contracts::admin::seal::{
    BottomCandidateHead, BottomRepairRequestBody, BottomRepairStrategy, SubmitControlMoveOutcome,
};

use super::bottom::bottom_entry_from;
use super::notary::notary_value_from_cell;
use super::notary_cell_for;

fn signer_descriptor(did: &str, seed: u8) -> arkret_wire::NotarySignerDescriptor {
    let did = arkret_identifiers::Did::new(did.to_owned()).unwrap();
    let actor_id = arkret_wire::project_did_to_core_id(&did).unwrap();
    let verification_method = arkret_wire::DidUrl::new(format!("{did}#notary-key")).unwrap();
    let verifying_key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key();
    soland_services::identity::ed25519_notary_signer_descriptor(
        actor_id,
        verification_method,
        verifying_key.as_bytes(),
    )
    .unwrap()
}

#[test]
fn notary_value_from_cell_defaults_to_service_id_when_absent() {
    let signer = signer_descriptor(
        "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service",
        11,
    );
    let resp = notary_value_from_cell(None, &signer).unwrap();
    assert_eq!(resp.kind_label(), "single_signer");
    assert_eq!(resp.notary, arkret_wire::NotaryValue::single_signer(signer));
    assert!(!resp.paused);
}

#[test]
fn notary_value_from_cell_reads_authoritative_single_signer_form() {
    let signer = signer_descriptor("did:web:alice.example", 12);
    let default_signer = signer_descriptor("did:web:server.example", 13);
    let mut v =
        serde_json::to_value(arkret_wire::NotaryValue::single_signer(signer.clone())).unwrap();
    v.as_object_mut()
        .unwrap()
        .insert("revocation_freshness_window_ms".to_owned(), json!(60000));
    v.as_object_mut()
        .unwrap()
        .insert("paused".to_owned(), json!(false));
    let resp = notary_value_from_cell(Some(&v), &default_signer).unwrap();
    assert_eq!(resp.kind_label(), "single_signer");
    assert_eq!(resp.notary, arkret_wire::NotaryValue::single_signer(signer));
    assert_eq!(resp.revocation_freshness_window_ms, Some(60000));
    assert!(!resp.paused);
    let j = serde_json::to_value(&resp).unwrap();
    assert_eq!(j["notary"]["kind"], "single_signer");
    assert_eq!(
        j["notary"]["signer"]["actor_id"],
        "ak:did_core:web:alice.example"
    );
    assert_eq!(j["revocation_freshness_window_ms"], 60000);
}

#[test]
fn notary_value_from_cell_reads_authoritative_threshold_form() {
    let members = vec![
        signer_descriptor("did:web:a.example", 21),
        signer_descriptor("did:web:b.example", 22),
        signer_descriptor("did:web:c.example", 23),
    ];
    let notary = arkret_wire::NotaryValue::Threshold {
        signers: members,
        threshold: 2,
        forensic_attribution: arkret_wire::ForensicAttribution::QuorumIntersection,
    };
    let v = serde_json::to_value(&notary).unwrap();
    let default_signer = signer_descriptor("did:web:s.example", 24);
    let resp = notary_value_from_cell(Some(&v), &default_signer).unwrap();
    assert_eq!(resp.kind_label(), "threshold");
    assert_eq!(resp.notary, notary);
}

#[test]
fn bottom_entry_from_camel_case_kind_normalises_to_snake_case() {
    // SDK serializes the Bottom variant as PascalCase via serde
    // default; the wire shape sodmin expects is snake_case. Our
    // shaping helper bridges the two.
    let bottom = json!({
        "kind": "Conflict",
        "event_ids": ["ak:event:a", "ak:event:b"],
        "details": "two heads"
    });
    let entry = bottom_entry_from(
        "ak:space:Aas_EcgKHABrLEjI4EJvOxHIXQVfHYZ_oP4Q_u3xuXRF",
        "ak:cell:ak.component.space.title.v1:ak:space:Aas_EcgKHABrLEjI4EJvOxHIXQVfHYZ_oP4Q_u3xuXRF",
        &bottom,
    );
    assert_eq!(entry.kind, "conflict");
    assert_eq!(entry.event_ids.len(), 2);
    assert_eq!(entry.candidate_heads.len(), 2);
    assert_eq!(entry.candidate_heads[0].event_id, "ak:event:a");
    assert_eq!(entry.details.as_deref(), Some("two heads"));
}

#[test]
fn bottom_entry_from_non_conflict_kind_has_no_candidate_heads() {
    let bottom = json!({
        "kind": "InvalidTransition",
        "event_ids": ["ak:event:x"],
        "details": "fsm rejected from invited→ban"
    });
    let entry = bottom_entry_from(
        "ak:space:Aas_EcgKHABrLEjI4EJvOxHIXQVfHYZ_oP4Q_u3xuXRF",
        "ak:cell:ak.component.member.state.v1:did.web.alice",
        &bottom,
    );
    assert_eq!(entry.kind, "invalid_transition");
    assert!(entry.candidate_heads.is_empty());
}

#[test]
fn bottom_repair_request_body_round_trips_through_serde() {
    let head_in = BottomRepairRequestBody {
        strategy: BottomRepairStrategy::HeadInWinner {
            head: BottomCandidateHead {
                event_id: "ak:event:abc".to_owned(),
                issuer_id: Some(
                    arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                ),
                hlc: None,
                summary: None,
            },
            recovery_capability_ref: "ak:grant:recovery".to_owned(),
            state_witness_ref: format!("ak:seal:sha256:{}", "11".repeat(32)),
            state_witness_inclusion_proof_ref: Some("ak:proof:state-witness".to_owned()),
        },
    };
    let j = serde_json::to_value(&head_in).unwrap();
    assert_eq!(
        j.get("strategy").and_then(Value::as_str),
        Some("head_in_winner")
    );
    let back: BottomRepairRequestBody = serde_json::from_value(j).unwrap();
    match back.strategy {
        BottomRepairStrategy::HeadInWinner {
            head,
            recovery_capability_ref,
            state_witness_ref,
            state_witness_inclusion_proof_ref,
        } => {
            assert_eq!(head.event_id, "ak:event:abc");
            assert_eq!(recovery_capability_ref, "ak:grant:recovery");
            assert!(state_witness_ref.starts_with("ak:seal:sha256:"));
            assert_eq!(
                state_witness_inclusion_proof_ref.as_deref(),
                Some("ak:proof:state-witness")
            );
        }
        #[allow(unreachable_patterns)]
        other => panic!("expected HeadInWinner, got {other:?}"),
    }
}

#[test]
fn notary_cell_for_builds_canonical_cell_ref() {
    let cell = notary_cell_for("ak:space:Aas_EcgKHABrLEjI4EJvOxHIXQVfHYZ_oP4Q_u3xuXRF").unwrap();
    assert_eq!(cell.as_str(), arkret_wire::REALM_NOTARY_CELL);
}

#[test]
fn admin_submit_move_response_serializes_status() {
    let r = SubmitControlMoveOutcome {
        control_move_id: "sha256:00".to_owned(),
        accepted: false,
        reason: Some("placeholder".to_owned()),
        seal_id: None,
        status: "placeholder".to_owned(),
        ..Default::default()
    };
    let s = serde_json::to_string(&r).unwrap();
    assert!(s.contains("\"status\":\"placeholder\""));
    assert!(s.contains("\"reason\":\"placeholder\""));
    assert!(!s.contains("seal_id"));
}
