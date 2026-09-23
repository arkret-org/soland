use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use proptest::prelude::*;

fn ed25519_detached_jws(signature: &[u8]) -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"Ed25519"}"#);
    let signature = URL_SAFE_NO_PAD.encode(signature);
    format!("{header}..{signature}")
}

proptest! {
    #[test]
    fn jws_shape_accepts_well_formed_detached_ed25519_signatures(
        payload in prop::collection::vec(any::<u8>(), 1..128),
        signature in prop::collection::vec(any::<u8>(), 64),
    ) {
        let jws = ed25519_detached_jws(&signature);
        prop_assume!(!jws.rsplit('.').next().unwrap_or_default().bytes().all(|b| b == b'A'));
        prop_assert!(soland_http::jws_verify::verify_jws_shape(
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
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"Ed25519"}"#);
        let signature = URL_SAFE_NO_PAD.encode(signature);
        let jws = format!("{header}.{attached_payload}.{signature}");
        let err = soland_http::jws_verify::verify_jws_shape(
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

}
