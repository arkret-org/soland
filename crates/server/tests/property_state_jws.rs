use std::collections::BTreeMap;

use arkret_sdk::CellRef;
use arkret_sdk::lattice::CellState;
use arkret_sdk::state::compute_state_root;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use proptest::prelude::*;
use serde_json::json;

fn eddsa_detached_jws(signature: &[u8]) -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA"}"#);
    let signature = URL_SAFE_NO_PAD.encode(signature);
    format!("{header}..{signature}")
}

proptest! {
    #[test]
    fn jws_shape_accepts_well_formed_detached_eddsa_signatures(
        payload in prop::collection::vec(any::<u8>(), 1..128),
        signature in prop::collection::vec(any::<u8>(), 64),
    ) {
        let jws = eddsa_detached_jws(&signature);
        prop_assume!(!jws.rsplit('.').next().unwrap_or_default().bytes().all(|b| b == b'A'));
        prop_assert!(soland::jws_verify::verify_jws_shape(
            &payload,
            &jws,
            "did:web:alice.example#k1",
            "did:web:alice.example",
        ).is_ok());
    }

    #[test]
    fn jws_shape_rejects_attached_payload_segment(
        payload in prop::collection::vec(any::<u8>(), 1..128),
        signature in prop::collection::vec(1u8..=255, 1..96),
        attached_payload in "[A-Za-z0-9_-]{1,32}",
    ) {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA"}"#);
        let signature = URL_SAFE_NO_PAD.encode(signature);
        let jws = format!("{header}.{attached_payload}.{signature}");
        let err = soland::jws_verify::verify_jws_shape(
            &payload,
            &jws,
            "did:web:alice.example#k1",
            "did:web:alice.example",
        ).unwrap_err();
        prop_assert_eq!(
            err,
            "invalid signature encoding: detached JWS must be header..signature with empty payload segment"
        );
    }

    #[test]
    fn state_root_is_independent_of_cell_insertion_order(
        entries in prop::collection::btree_map("[a-z0-9_]{1,16}", any::<u32>(), 1..32),
    ) {
        let mut forward = BTreeMap::new();
        for (subject, value) in &entries {
            let cell = CellRef::new(format!("ak:cell:ak.component.test.prop.v1:{subject}"))
                .expect("generated cell ref is valid");
            forward.insert(cell, CellState::Value(json!({"value": value})));
        }

        let mut reverse = BTreeMap::new();
        for (subject, value) in entries.iter().rev() {
            let cell = CellRef::new(format!("ak:cell:ak.component.test.prop.v1:{subject}"))
                .expect("generated cell ref is valid");
            reverse.insert(cell, CellState::Value(json!({"value": value})));
        }

        let forward_root = compute_state_root(&forward).expect("forward root");
        let reverse_root = compute_state_root(&reverse).expect("reverse root");
        prop_assert_eq!(forward_root, reverse_root);
    }
}
