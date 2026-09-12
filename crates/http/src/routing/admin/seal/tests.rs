use serde_json::json;

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
    assert_eq!(
        resp.notary,
        arkret_wire::NotaryValue::new(signer, 0).unwrap()
    );
    assert!(!resp.paused);
}

#[test]
fn notary_value_from_cell_reads_authoritative_single_signer() {
    let signer = signer_descriptor("did:web:alice.example", 12);
    let default_signer = signer_descriptor("did:web:server.example", 13);
    let expected = arkret_wire::NotaryValue::new(signer.clone(), 0).unwrap();
    let mut v = serde_json::to_value(&expected).unwrap();
    v.as_object_mut()
        .unwrap()
        .insert("paused".to_owned(), json!(false));
    let resp = notary_value_from_cell(Some(&v), &default_signer).unwrap();
    assert_eq!(resp.notary, expected);
    assert!(!resp.paused);
    let j = serde_json::to_value(&resp).unwrap();
    assert!(j["notary"].get("kind").is_none());
    assert_eq!(
        j["notary"]["signer"]["actor_id"],
        json!({"kind": "service", "service_id": "ak:did_core:web:alice.example"})
    );
}

#[test]
fn bottom_entry_from_reads_the_kind_the_sdk_emits() {
    let realm = arkret_wire::RealmId::new(
        "ak:realm:Aas_EcgKHABrLEjI4EJvOxHIXQVfHYZ_oP4Q_u3xuXRF".to_owned(),
    )
    .unwrap();
    let cell = arkret_wire::CellRef::new(format!(
        "ak:cell:ak.component.space.title.v1:{}",
        realm.as_str()
    ))
    .unwrap();
    let first = arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [1; 32]);
    let second = arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [2; 32]);
    let bottom = arkret_wire::Bottom::conflict(
        vec![cell.clone()],
        vec![
            arkret_wire::CausalHead {
                event_id: first.clone(),
                value: json!("a"),
            },
            arkret_wire::CausalHead {
                event_id: second,
                value: json!("b"),
            },
        ],
    );
    let entry = bottom_entry_from(&realm, &cell, &bottom);
    assert_eq!(entry.kind, arkret_wire::BottomKind::Conflict);
    assert_eq!(entry.candidate_heads.len(), 2);
    assert_eq!(entry.candidate_heads[0].event_id, first);
    assert_eq!(entry.candidate_heads[0].value, json!("a"));
}

#[test]
fn notary_cell_for_builds_canonical_cell_ref() {
    let cell = notary_cell_for("ak:space:Aas_EcgKHABrLEjI4EJvOxHIXQVfHYZ_oP4Q_u3xuXRF").unwrap();
    assert_eq!(cell.as_str(), arkret_wire::REALM_NOTARY_CELL);
}
