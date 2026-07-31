use super::*;

pub(super) async fn validate_capability_grant_proofs(
    state: &AppState,
    session: &SessionRecord,
    kind: &str,
    actor_id: &str,
    object: &serde_json::Map<String, Value>,
    internal_admission: Option<&crate::routing::events::event_log::submit::InternalEventAdmission>,
) -> Result<(), EventValidationError> {
    if kind != arkret_wire::events::EventKind::CAPABILITY_GRANT {
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
    let Some(grant) = payload.grant else {
        // The active schema also permits the compact grant-id/actions/resource
        // carrier. It has no nested proof object; its Event proof remains the
        // complete authenticity boundary.
        return Ok(());
    };
    if grant.id != payload.grant_id {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "capability grant id does not match payload.grant_id",
        ));
    }
    if grant.issuer.as_str() != actor_id {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "invalid_proof",
            "capability grant issuer must equal the Event actor",
        ));
    }
    if grant.proofs.is_empty() {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "capability grant must carry an issuer proof",
        ));
    }

    for proof in &grant.proofs {
        proof.validate_production().map_err(|error| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_proof",
                format!("invalid capability grant proof: {error}"),
            )
        })?;
        if proof.proof_purpose.is_some()
            && proof.proof_purpose != Some(arkret_wire::PayloadProofPurpose::IssuerAttestation)
        {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_proof",
                "capability grant proof purpose must be issuer_attestation",
            ));
        }
        // `did-usage-and-verification.md` §2.2: the method MUST be a DID URL
        // under the issuer, never the bare issuer DID.
        if !proof
            .verification_method
            .starts_with(&format!("{}#", grant.issuer))
        {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "invalid_proof",
                "capability grant proof verification method must be rooted in the issuer",
            ));
        }
        let binding = grant
            .canonical_proof_binding_bytes(proof)
            .map_err(|error| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_proof",
                    format!("invalid capability grant proof binding: {error}"),
                )
            })?;
        if !super::proofs::verify_with_federated_signer_evidence(
            internal_admission,
            session,
            object,
            &proof.verification_method,
            &binding,
            &proof.jws,
        )? {
            crate::jws_verify::verify_principal_authorized_jws_ed25519_async(
                &binding,
                &proof.jws,
                &proof.verification_method,
                grant.issuer.as_str(),
                state,
            )
            .await
            .map_err(|error| {
                tracing::debug!(%error, "capability grant proof JWS verification failed");
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_proof",
                    "capability grant proof JWS verification failed",
                )
            })?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use serde_json::json;
    use soland_storage_postgres::Db;

    use super::*;

    fn state() -> AppState {
        AppState::new(
            crate::config::AppConfig {
                object_storage: crate::config::ObjectStorageConfig::local(
                    std::env::temp_dir().join("soland-capability-grant-proof-test"),
                ),
                did_resolver_allow_methods: vec!["key".to_owned()],
                jws_replay_window_seconds: 0,
                ..crate::config::AppConfig::test_default()
            },
            Db { pool: None },
        )
    }

    fn signed_payload() -> (String, Value) {
        let signing_key = SigningKey::from_bytes(&[31_u8; 32]);
        let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            signing_key.verifying_key().as_bytes(),
        );
        let issuer = format!("did:key:{multibase}");
        let verification_method =
            arkret_wire::DidUrl::new(format!("{issuer}#{multibase}")).expect("fixture DID URL");
        let mut grant: arkret_models_collaboration::governance::grant_constraint::CapabilityGrant =
            serde_json::from_value(json!({
                "id": "ak:grant:01904100-0000-7000-8000-000000000013",
                "schema": "ak.schema.capability.v1",
                "realm_id": "ak:realm:01904100-0000-7000-8000-000000000012",
                "issuer": issuer,
                "subject": issuer,
                "actions": ["ak.realm.configure"],
                "resources": [{
                    "kind": "realm",
                    "realm_id": "ak:realm:01904100-0000-7000-8000-000000000012",
                    "match_scope": "realm_wide"
                }],
                "issued_at": "2026-07-21T08:00:00.000Z",
                "proofs": []
            }))
            .expect("grant fixture");
        let mut proof = arkret_wire::PayloadProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method,
            payload_digest: grant.payload_digest().expect("grant digest"),
            created_at: chrono::DateTime::parse_from_rfc3339("2026-07-21T08:00:00.000Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            domain: None,
            audience: None,
            proof_purpose: Some(arkret_wire::PayloadProofPurpose::IssuerAttestation),
            jws: String::new(),
        };
        proof.jws = arkret_signatures::sign_eddsa_detached_jws(
            &signing_key,
            &grant
                .canonical_proof_binding_bytes(&proof)
                .expect("grant proof binding"),
        )
        .expect("grant proof signature");
        grant.proofs.push(proof);
        let grant_id = grant.id.clone();
        (
            issuer,
            json!({
                "grant_id": grant_id,
                "grant": grant
            }),
        )
    }

    fn session(actor: &str, state: &AppState) -> SessionRecord {
        let created_at = chrono::Utc::now();
        SessionRecord {
            token_hash: "capability-grant-proof-test".to_owned(),
            actor: actor.to_owned(),
            device_id: "ak:device:01904100-0000-7000-8000-000000000001".to_owned(),
            audience: state.service_id().clone(),
            session_public_key: None,
            agent_session: None,
            expires_at: created_at + chrono::Duration::minutes(1),
            created_at,
            revoked_at: None,
        }
    }

    #[tokio::test]
    async fn accepts_valid_issuer_attestation_and_rejects_digest_drift() {
        let state = state();
        let (issuer, mut payload) = signed_payload();
        let session = session(&issuer, &state);
        let event = json!({"payload": payload.clone()});
        validate_capability_grant_proofs(
            &state,
            &session,
            arkret_wire::events::EventKind::CAPABILITY_GRANT,
            &issuer,
            event.as_object().unwrap(),
            None,
        )
        .await
        .expect("valid capability grant proof");

        payload["grant"]["proofs"][0]["payload_digest"] =
            json!(format!("sha256:{}", "0".repeat(64)));
        let event = json!({"payload": payload});
        assert!(
            validate_capability_grant_proofs(
                &state,
                &session,
                arkret_wire::events::EventKind::CAPABILITY_GRANT,
                &issuer,
                event.as_object().unwrap(),
                None,
            )
            .await
            .is_err()
        );
    }

    // did-usage-and-verification.md §2.2 — `proof.verification_method` MUST be
    // a `#fragment` DID URL rooted in the issuer. The bare issuer DID names no
    // concrete verification method and must be refused.
    #[tokio::test]
    async fn rejects_bare_issuer_did_as_verification_method() {
        let state = state();
        let (issuer, mut payload) = signed_payload();
        let session = session(&issuer, &state);

        // Two different rejections, on purpose:
        //
        // * the bare issuer DID no longer even decodes — `CapabilityGrant.proofs[]
        //   .verification_method` is a typed `DidUrl`, so wire ingress refuses it as a schema
        //   violation before any rooting logic runs;
        // * a sibling DID that merely shares the issuer's prefix decodes fine and is refused by the
        //   rooting gate.
        let cases: [(String, StatusCode, &str); 2] = [
            (issuer.clone(), StatusCode::BAD_REQUEST, "capability grant"),
            (
                format!("{issuer}.evil#k1"),
                StatusCode::FORBIDDEN,
                "must be rooted in the issuer",
            ),
        ];
        for (verification_method, expected_status, expected_fragment) in cases {
            payload["grant"]["proofs"][0]["verification_method"] = json!(verification_method);
            let event = json!({"payload": payload.clone()});
            let error = validate_capability_grant_proofs(
                &state,
                &session,
                arkret_wire::events::EventKind::CAPABILITY_GRANT,
                &issuer,
                event.as_object().unwrap(),
                None,
            )
            .await
            .expect_err("verification method must be a DID URL under the issuer");
            assert_eq!(
                error.status, expected_status,
                "{verification_method}: {}",
                error.message
            );
            assert!(
                error.message.contains(expected_fragment),
                "{verification_method}: {}",
                error.message
            );
        }
    }
}
