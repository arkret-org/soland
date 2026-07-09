use super::*;

pub(crate) async fn validate_event_proofs(
    object: &serde_json::Map<String, Value>,
    state: &AppState,
    session: &SessionRecord,
    actor_id: &str,
    expected_payload_digest: &str,
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
    // Proof validation forks on `state.config.development_mode`:
    // - **Production** (`development_mode=false`): EVERY proof MUST be a full detached-JWS proof
    //   with `kind`/`alg`/`verification_method`/ `event_digest`/`created_at`/`jws`, hashing the
    //   full canonical envelope. The `type=="dev-proof"` and payload-only hash forms are NOT
    //   accepted under any circumstance — a malicious client claiming `type="dev-proof"` in
    //   production fails-closed here.
    // - **Development** (`development_mode=true`): the minimal dev-proof shape (`type="dev-proof"`,
    //   `verification_method`, `payload_digest`-of-payload) is also accepted so integration
    //   fixtures round-trip without keying.
    let is_production = !state.config.development_mode;
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
    let proof_root =
        event_string_field(object, &["executed_by"]).unwrap_or_else(|| actor_id.to_owned());
    for proof in proofs {
        let Some(proof_object) = proof.as_object() else {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_proof",
                "event proofs must be JSON objects",
            ));
        };
        // Production NEVER falls into the dev-proof branch, even if the client
        // claims `type="dev-proof"`. That stops a downgrade attack where a
        // production server is tricked into accepting a weak proof.
        let is_dev_proof = !is_production
            && event_string_field(proof_object, &["type"]).as_deref() == Some("dev-proof");
        let required_fields: &[&str] = if is_dev_proof {
            &["verification_method", "payload_digest"]
        } else {
            &[
                "kind",
                "alg",
                "verification_method",
                "event_digest",
                "created_at",
                "jws",
            ]
        };
        for field in required_fields {
            if !proof_object.contains_key(*field) {
                return Err(event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_proof",
                    "event proof is missing required fields",
                ));
            }
        }
        if !is_dev_proof
            && event_string_field(proof_object, &["kind"]).as_deref() != Some("detached_jws")
        {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_proof",
                "event proof kind must be detached_jws",
            ));
        }
        if !is_dev_proof && event_string_field(proof_object, &["alg"]).as_deref() != Some("EdDSA") {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_proof",
                "event proof alg must be EdDSA",
            ));
        }
        let proof_digest_key = if is_dev_proof {
            "payload_digest"
        } else {
            "event_digest"
        };
        let proof_event_digest =
            event_string_field(proof_object, &[proof_digest_key]).ok_or_else(|| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_proof",
                    "proof event_digest is required",
                )
            })?;
        // Production: the proof's event_digest MUST match the canonical
        // envelope digest. Dev-only: also accept the payload-only form under
        // the same digest suite so test fixtures keep round-tripping.
        // Production never falls back.
        let payload_only_hash_accept = if is_dev_proof {
            let expected_suite = expected_payload_digest
                .split_once(':')
                .map(|(suite, _)| suite)
                .unwrap_or("sha256");
            object.get("payload").map(|payload| {
                let bytes = canonical::canonical_json_bytes(payload).unwrap_or_default();
                cokret_sdk::canonical::digest_with_suite(expected_suite, &bytes)
                    .unwrap_or_else(|_| cokret_sdk::canonical::sha256_digest(&bytes))
            })
        } else {
            None
        };
        if proof_event_digest != expected_payload_digest
            && payload_only_hash_accept.as_deref() != Some(&proof_event_digest)
        {
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
        if verification_method != proof_root
            && !verification_method.starts_with(&format!("{proof_root}#"))
        {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "invalid_proof",
                "proof verification method must be rooted in the proof signer (executed_by when present, else actor_id)",
            ));
        }
        if is_production {
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
            // High-risk path: enforce DID document freshness before event
            // proof verification (fail-closed-on-stale). Stale or missing
            // evidence must not be used for signature verification. The signer
            // DID is `proof_root` (the enrollment authority for service_attested
            // device.authorize, else actor_id); freshness + key resolution both
            // target it. did:key signers have no persisted webvh record and are
            // resolved purely cryptographically by the SDK verifier below, so
            // the freshness gate (which only covers cached webvh documents)
            // only applies to webvh signers.
            let signer_did = cokret_sdk::Did::new(proof_root.clone()).map_err(|error| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_proof",
                    format!("event proof signer DID is not a valid DID: {error}"),
                )
            })?;
            if signer_did.method() != "key" {
                crate::jws_verify::enforce_high_risk_did_freshness(state, &signer_did)
                    .await
                    .map_err(|reason| {
                        tracing::debug!(%reason, "event proof DID freshness gate failed");
                        event_validation_error(
                            StatusCode::BAD_REQUEST,
                            "stale_did_document",
                            "event proof DID document is stale or unavailable for verification",
                        )
                    })?;
            }
            crate::jws_verify::verify_jws_ed25519_async(
                &proof_binding_bytes,
                &jws,
                &verification_method,
                signer_did.as_str(),
                state,
            )
            .await
            .map_err(|reason| {
                tracing::debug!(%reason, "event proof JWS verification failed");
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_proof",
                    "event proof JWS verification failed",
                )
            })?;
        }
    }
    Ok(())
}

pub(super) fn event_proof_binding_bytes(
    event_digest: &str,
    actor_id: &str,
    verification_method: &str,
    created_at: &str,
    proof_object: &serde_json::Map<String, Value>,
) -> Result<Vec<u8>, EventValidationError> {
    let mut binding = serde_json::Map::new();
    // encoding.md §2: the Event proof binding carries the fixed signing-context
    // domain tag "ck-event-proof-v1" (mirrors cokret_sdk Proof::binding_object)
    // so an Event proof cannot be confused with another proof family's binding.
    binding.insert("context".to_owned(), json!("ck-event-proof-v1"));
    binding.insert("event_digest".to_owned(), json!(event_digest));
    binding.insert("actor_id".to_owned(), json!(actor_id));
    binding.insert("verification_method".to_owned(), json!(verification_method));
    binding.insert("created_at".to_owned(), json!(created_at));
    for optional in ["domain", "audience"] {
        if let Some(value) = proof_object.get(optional) {
            binding.insert(optional.to_owned(), value.clone());
        }
    }
    canonical::canonical_json_bytes(&Value::Object(binding)).map_err(|error| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            format!("proof binding canonicalization failed: {error}"),
        )
    })
}
