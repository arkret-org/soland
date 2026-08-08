use serde_json::{Value, json};
use soland_contracts::admin::seal::{
    BottomCandidateHead, BottomRepairRequestBody, BottomRepairStrategy, SubmitControlMoveOutcome,
};

use super::bottom::bottom_entry_from;
use super::notary::notary_value_from_cell;
use super::notary_cell_for;

#[test]
fn notary_value_from_cell_defaults_to_service_id_when_absent() {
    let resp = notary_value_from_cell(
        None,
        "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service",
    )
    .unwrap();
    assert_eq!(resp.kind_raw, "single_did");
    assert_eq!(
        resp.single_did.as_deref(),
        Some(
            "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service"
        )
    );
    assert!(!resp.paused);
}

#[test]
fn notary_value_from_cell_reads_authoritative_single_did_form() {
    let v = json!({
        "kind": "single_did",
        "did": "did:web:alice.example",
        "revocation_freshness_window_ms": 60000,
        "paused": false,
    });
    let resp = notary_value_from_cell(Some(&v), "did:web:server").unwrap();
    assert_eq!(resp.kind_raw, "single_did");
    assert_eq!(resp.single_did.as_deref(), Some("did:web:alice.example"));
    assert_eq!(resp.revocation_freshness_window_ms, Some(60000));
    assert!(!resp.paused);
    // Serialized admin shape carries the shared DTO field names.
    let j = serde_json::to_value(&resp).unwrap();
    assert_eq!(j["kind_raw"], "single_did");
    assert_eq!(j["single_did"], "did:web:alice.example");
    assert_eq!(j["revocation_freshness_window_ms"], 60000);
}

#[test]
fn notary_value_from_cell_reads_authoritative_threshold_form() {
    let v = json!({
        "kind": "threshold",
        "threshold": 2,
        "members": ["did:ak:a", "did:ak:b", "did:ak:c"],
        "forensic_attribution": "quorum_intersection",
    });
    let resp = notary_value_from_cell(Some(&v), "did:web:s").unwrap();
    assert_eq!(resp.kind_raw, "threshold");
    assert_eq!(resp.threshold_k, Some(2));
    // `n` is derived from the committee size now (no wire `n`).
    assert_eq!(resp.threshold_n, Some(3));
    assert_eq!(resp.threshold_dids.len(), 3);
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
        "ak:space:01904100-0000-8000-8000-2dd3431bd65a",
        "ak:cell:ak.component.space.title.v1:ak:space:01904100-0000-8000-8000-2dd3431bd65a",
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
        "ak:space:01904100-0000-8000-8000-2dd3431bd65a",
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
                issuer: Some("did:ak:alice".to_owned()),
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
    let cell = notary_cell_for("ak:space:01904100-0000-8000-8000-2dd3431bd65a").unwrap();
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
