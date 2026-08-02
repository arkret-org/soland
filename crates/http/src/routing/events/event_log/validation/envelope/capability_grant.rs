use super::*;

/// Enforce the grant-body invariants that are bound by the Event proof.
///
/// `CapabilityGrant` deliberately has no nested `proofs` carrier: the only
/// durable issuer signature is the surrounding Event envelope proof.
pub(super) fn validate_capability_grant_body(
    kind: &str,
    actor_id: &str,
    object: &serde_json::Map<String, Value>,
) -> Result<(), EventValidationError> {
    if kind != arkret_wire::EventKind::CAPABILITY_GRANT {
        return Ok(());
    }
    let payload: arkret_models_collaboration::events_payloads::CapabilityGrantPayload =
        serde_json::from_value(object.get("payload").cloned().unwrap_or(Value::Null)).map_err(
            |error| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    format!("invalid capability grant payload: {error}"),
                )
            },
        )?;
    if payload.grant.id != payload.grant_id {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "capability grant id does not match payload.grant_id",
        ));
    }
    if payload.grant.issuer.as_str() != actor_id {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "invalid_proof",
            "capability grant issuer must equal the Event actor",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn event(actor: &str) -> Value {
        json!({
            "payload": {
                "grant_id": "ak:grant:01904100-0000-7000-8000-000000000013",
                "grant": {
                    "id": "ak:grant:01904100-0000-7000-8000-000000000013",
                    "schema": "ak.schema.capability.v1",
                    "realm_id": "ak:realm:01904100-0000-7000-8000-000000000012",
                    "issuer": actor,
                    "subject": actor,
                    "actions": ["ak.realm.configure"],
                    "resources": [{
                        "kind": "realm",
                        "realm_id": "ak:realm:01904100-0000-7000-8000-000000000012",
                        "match_scope": "realm_wide"
                    }],
                    "issued_at": "2026-07-21T08:00:00.000Z",
                    "issuer_authority_refs": [{
                        "kind": "realm_root",
                        "realm_id": "ak:realm:01904100-0000-7000-8000-000000000012",
                        "cell_ref": "ak:cell:ak.component.realm.authority_root.v1:null",
                        "controller_epoch_at_issuance": 0,
                        "authority_generation": 0
                    }]
                }
            }
        })
    }

    #[test]
    fn accepts_grant_without_a_nested_proof() {
        let actor = "did:key:z6Mktest";
        let event = event(actor);
        validate_capability_grant_body(
            arkret_wire::EventKind::CAPABILITY_GRANT,
            actor,
            event.as_object().unwrap(),
        )
        .expect("the Event proof is the sole durable signature");
    }

    #[test]
    fn rejects_legacy_nested_proofs_and_actor_mismatch() {
        let actor = "did:key:z6Mktest";
        let mut legacy = event(actor);
        legacy["payload"]["grant"]["proofs"] = json!([]);
        assert!(
            validate_capability_grant_body(
                arkret_wire::EventKind::CAPABILITY_GRANT,
                actor,
                legacy.as_object().unwrap(),
            )
            .is_err()
        );

        let event = event(actor);
        assert!(
            validate_capability_grant_body(
                arkret_wire::EventKind::CAPABILITY_GRANT,
                "did:key:z6Mkother",
                event.as_object().unwrap(),
            )
            .is_err()
        );
    }
}
