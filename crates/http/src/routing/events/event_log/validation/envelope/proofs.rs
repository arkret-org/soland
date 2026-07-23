use super::minimal_metadata_author::{
    minimal_metadata_author_context, validate_minimal_metadata_author_proof,
};
use super::*;
use crate::routing::events::event_log::submit::InternalEventAdmission;

pub(crate) async fn validate_event_proofs(
    object: &serde_json::Map<String, Value>,
    state: &AppState,
    session: &SessionRecord,
    actor_id: &str,
    expected_payload_digest: &str,
    internal_admission: Option<&InternalEventAdmission>,
) -> Result<(), EventValidationError> {
    let proofs = object
        .get("proofs")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "missing_param",
                "proofs are required",
            )
        })?;
    if proofs.is_empty() {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "missing_param",
            "proofs must contain at least one proof",
        ));
    }
    // Durable Events always carry the SDK Event proof shape. Development mode
    // changes deployment trust roots, never the protocol transcript.
    // Device-identity B-model (device-lifecycle.md §5.4): a delegated-execution
    // envelope (`executed_by` present) is signed by the executing authority's
    // key, NOT by a key rooted in `actor_id`. When `executed_by` is set the
    // proof `verification_method` MUST be rooted in `executed_by` and the JWS
    // is verified against the authority DID; the signed proof-binding transcript
    // still names `actor_id` (the record subject) per encoding.md §6. Absent
    // `executed_by`, the original actor_id rooting applies. The envelope-level
    // schema already requires `authorization_ref` whenever `executed_by` is
    // present, and the actor/executed_by DID validity + vm-DID==executed_by
    // checks ran earlier in this function.
    let ordinary_proof_root =
        event_string_field(object, &["executed_by"]).unwrap_or_else(|| actor_id.to_owned());
    let root_anchor_method = resolve_event_root_anchor_method(state, object, actor_id).await?;
    // §2.10.3 — minimal-metadata content Events authenticate authorship
    // against the active MLS LeafNode at the envelope's `(group_id, epoch,
    // group_state_ref)` instead of the DID-document / directory path. The
    // context is only `Some` when the Realm positively declared the
    // minimal-metadata profile AND the payload carries an encrypted-content
    // envelope.
    let minimal_metadata_context = minimal_metadata_author_context(object, state).await;
    for proof in proofs {
        let Some(proof_object) = proof.as_object() else {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_proof",
                "event proofs must be JSON objects",
            ));
        };
        let required_fields: &[&str] = &[
            "kind",
            "alg",
            "verification_method",
            "event_digest",
            "created_at",
            "jws",
        ];
        for field in required_fields {
            if !proof_object.contains_key(*field) {
                return Err(event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_proof",
                    "event proof is missing required fields",
                ));
            }
        }
        if event_string_field(proof_object, &["kind"]).as_deref() != Some("detached_jws") {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_proof",
                "event proof kind must be detached_jws",
            ));
        }
        if event_string_field(proof_object, &["alg"]).as_deref() != Some("EdDSA") {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_proof",
                "event proof alg must be EdDSA",
            ));
        }
        let proof_event_digest =
            event_string_field(proof_object, &["event_digest"]).ok_or_else(|| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_proof",
                    "proof event_digest is required",
                )
            })?;
        if proof_event_digest != expected_payload_digest {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "proof_event_digest_mismatch",
                "proof event_digest does not match the event payload",
            ));
        }
        validate_event_audience_fields(proof_object, state, session)?;
        let verification_method = event_string_field(proof_object, &["verification_method"])
            .ok_or_else(|| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_proof",
                    "proof verification_method is required",
                )
            })?;
        let signer_controller = if let Some(expected_root_method) = root_anchor_method.as_deref() {
            if verification_method != expected_root_method {
                return Err(event_validation_error(
                    StatusCode::FORBIDDEN,
                    "invalid_proof",
                    "root-anchored Event proof must use the active update authority from the referenced DID entry",
                ));
            }
            verification_method
                .split_once('#')
                .map_or(verification_method.as_str(), |(did, _)| did)
                .to_owned()
        } else {
            if verification_method != ordinary_proof_root
                && !verification_method.starts_with(&format!("{ordinary_proof_root}#"))
            {
                return Err(event_validation_error(
                    StatusCode::FORBIDDEN,
                    "invalid_proof",
                    "proof verification method must be rooted in the proof signer (executed_by when present, else actor_id)",
                ));
            }
            ordinary_proof_root.clone()
        };
        {
            let jws = event_string_field(proof_object, &["jws"]).ok_or_else(|| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_proof",
                    "proof jws is required",
                )
            })?;
            let created_at =
                event_string_field(proof_object, &["created_at"]).ok_or_else(|| {
                    event_validation_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_proof",
                        "proof created_at is required",
                    )
                })?;
            // The signed proof-binding transcript names `actor_id` (record
            // subject) regardless of who signed it (encoding.md §6); only the
            // resolved signer DID (`proof_root`) switches to `executed_by` for
            // delegated execution.
            let proof_binding_bytes = event_proof_binding_bytes(
                &proof_event_digest,
                actor_id,
                &verification_method,
                &created_at,
                proof_object,
            )?;
            // §2.10.3 minimal-metadata branch: LeafNode trust anchor, pure
            // did:key fragment key material, zero DID-freshness / resolver /
            // principal-directory calls. Mutually exclusive with the
            // DID-document path below.
            if let Some(context) = &minimal_metadata_context {
                validate_minimal_metadata_author_proof(
                    state,
                    context,
                    object,
                    actor_id,
                    &verification_method,
                    &proof_binding_bytes,
                    &jws,
                )
                .await?;
                continue;
            }
            // §5.4/§8.2: `{principal}#{device_id}` resolves from the current
            // device-set projection. DID control/delegation methods resolve
            // from the DID document and retain the high-risk freshness gate.
            // Both branches use the SDK detached-JWS verifier.
            if !verify_with_federated_signer_evidence(
                internal_admission,
                session,
                object,
                &verification_method,
                &proof_binding_bytes,
                &jws,
            )? {
                crate::jws_verify::verify_principal_authorized_jws_ed25519_async(
                    &proof_binding_bytes,
                    &jws,
                    &verification_method,
                    &signer_controller,
                    state,
                )
                .await
                .map_err(|error| {
                    use crate::jws_verify::PrincipalAuthorizedJwsError;

                    match error {
                        PrincipalAuthorizedJwsError::HighRiskDidFreshness(reason) => {
                            tracing::debug!(%reason, "event proof DID freshness gate failed");
                            event_validation_error(
                                StatusCode::BAD_REQUEST,
                                "stale_did_document",
                                "event proof DID document is stale or unavailable for verification",
                            )
                        }
                        PrincipalAuthorizedJwsError::Verification(reason) => {
                            tracing::debug!(%reason, "event proof JWS verification failed");
                            event_validation_error(
                                StatusCode::BAD_REQUEST,
                                "invalid_proof",
                                "event proof JWS verification failed",
                            )
                        }
                    }
                })?;
            }
        }
    }
    Ok(())
}

pub(super) fn verify_with_federated_signer_evidence(
    internal_admission: Option<&InternalEventAdmission>,
    session: &SessionRecord,
    object: &serde_json::Map<String, Value>,
    verification_method: &str,
    canonical_bytes: &[u8],
    jws: &str,
) -> Result<bool, EventValidationError> {
    let Some(evidence) = internal_admission
        .and_then(|admission| admission.signer_key_evidence(session, object, verification_method))
    else {
        return Ok(false);
    };
    let multibase = evidence
        .device_signing_key
        .as_str()
        .strip_prefix("did:key:")
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_proof",
                "federated signer evidence must carry an Ed25519 did:key",
            )
        })?;
    let material = arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
        value: multibase.to_owned(),
    };
    arkret_signatures::Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(jws, canonical_bytes, &material)
        .map_err(|error| {
            tracing::debug!(%error, "federated Event proof JWS verification failed");
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_proof",
                "federated Event proof JWS verification failed",
            )
        })?;
    Ok(true)
}

pub(super) fn event_proof_binding_bytes(
    event_digest: &str,
    actor_id: &str,
    verification_method: &str,
    created_at: &str,
    proof_object: &serde_json::Map<String, Value>,
) -> Result<Vec<u8>, EventValidationError> {
    let proof: arkret_wire::Proof = serde_json::from_value(Value::Object(proof_object.clone()))
        .map_err(|error| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_proof",
                format!("event proof is not an SDK Proof: {error}"),
            )
        })?;
    if proof.event_digest.as_str() != event_digest
        || proof.verification_method != verification_method
        || arkret_canonical::format_timestamp_canonical(proof.created_at) != created_at
    {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "event proof binding fields are inconsistent",
        ));
    }
    let actor = arkret_identifiers::Did::new(actor_id.to_owned()).map_err(|error| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            format!("event actor_id is not a valid DID: {error}"),
        )
    })?;
    proof.canonical_binding_bytes(&actor).map_err(|error| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            format!("proof binding canonicalization failed: {error}"),
        )
    })
}
