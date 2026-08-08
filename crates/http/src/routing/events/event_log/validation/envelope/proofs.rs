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
    digest_suite: arkret_canonical::DigestSuite,
    // The Event's canonical bytes with `proofs` / `unsigned` stripped — exactly
    // what `expected_payload_digest` was computed over. The SDK Event-proof
    // verifier re-derives `event_digest` from these and constant-time compares
    // it to `proof.event_digest`, so the transcript the signature covers is
    // never reconstructed by hand at this call site.
    envelope_bytes: &[u8],
    realm_bootstrap_contexts: &[RealmBootstrapBatchContext],
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
    let root_anchored_candidate_key = (object.get("kind").and_then(Value::as_str)
        == Some(arkret_wire::EventKind::DEVICE_AUTHORIZE)
        && object
            .get("payload")
            .and_then(Value::as_object)
            .and_then(|payload| payload.get("authorization_binding_kind"))
            .and_then(Value::as_str)
            == Some("root_anchored"))
    .then(|| {
        realm_bootstrap_contexts.iter().find_map(|context| {
            let candidate_key = context.identity_anchor_candidate_device_key.as_ref()?;
            (context.actor_id == actor_id
                && object
                    .get("payload")
                    .and_then(Value::as_object)
                    .and_then(|payload| payload.get("device_public_key"))
                    .and_then(Value::as_str)
                    == Some(candidate_key.as_str()))
            .then(|| candidate_key.clone())
        })
    })
    .flatten();
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
        // §2.2 — `proof.verification_method` is a DID URL: `{did}#{fragment}`.
        // Parsing it here (instead of prefix-matching a raw string) is what
        // makes the bare-DID form unrepresentable: a value equal to the signer
        // DID with no fragment names no key and is rejected before any
        // signature check.
        let verification_method_url = arkret_wire::DidUrl::new(verification_method.clone())
            .map_err(|error| {
                event_validation_error(
                    StatusCode::FORBIDDEN,
                    "invalid_proof",
                    format!("proof verification_method must be a DID URL: {error}"),
                )
            })?;
        let method_root = verification_method_url
            .as_str()
            .split_once('#')
            .map(|(did, _)| did)
            .expect("DidUrl always carries a fragment");
        if root_anchored_candidate_key.is_some() {
            let candidate_device_id = object
                .get("payload")
                .and_then(Value::as_object)
                .and_then(|payload| payload.get("device_id"))
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    event_validation_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_proof",
                        "root-anchored device authorization requires device_id",
                    )
                })?;
            let expected_method = format!("{actor_id}#{candidate_device_id}");
            if verification_method_url.as_str() != expected_method {
                return Err(event_validation_error(
                    StatusCode::FORBIDDEN,
                    "invalid_proof",
                    "root-anchored candidate Event proof must use principal#device_id",
                ));
            }
        }
        let signer_controller = if let Some(expected_root_method) = root_anchor_method.as_deref() {
            if verification_method_url != expected_root_method {
                return Err(event_validation_error(
                    StatusCode::FORBIDDEN,
                    "invalid_proof",
                    "root-anchored Event proof must use the active update authority from the referenced DID entry",
                ));
            }
            method_root.to_owned()
        } else {
            if method_root != ordinary_proof_root {
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
            let (typed_proof, actor_did, proof_binding_bytes) = event_proof_binding_bytes(
                &proof_event_digest,
                actor_id,
                &verification_method,
                &created_at,
                proof_object,
            )?;
            // Genesis and re-anchor authorize their candidate key in the same
            // atomic unit in which it first signs. The durable device
            // directory therefore cannot resolve it yet. Use a unit-local
            // overlay only after the anchor/payload/possession precheck has
            // succeeded; never reinterpret the did:key as the proof method.
            if let Some(candidate_key) = root_anchored_candidate_key.as_deref() {
                let multibase = candidate_key.strip_prefix("did:key:").ok_or_else(|| {
                    event_validation_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_proof",
                        "candidate device key must use did:key multibase encoding",
                    )
                })?;
                let material = arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
                    value: multibase.to_owned(),
                };
                arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
                    &typed_proof,
                    envelope_bytes,
                    &actor_did,
                    &material,
                    digest_suite,
                )
                .map_err(|error| {
                    tracing::debug!(%error, "candidate device Event proof verification failed");
                    event_validation_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_proof",
                        "candidate device Event proof verification failed",
                    )
                })?;
                continue;
            }
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
            if verify_with_active_agent_session(
                state,
                session,
                &signer_controller,
                &verification_method,
                &proof_binding_bytes,
                &jws,
            )
            .await?
            {
                continue;
            }
            if verify_with_federated_agent_signer_evidence(
                internal_admission,
                session,
                object,
                &verification_method,
                &proof_binding_bytes,
                &jws,
            )? {
                continue;
            }
            if object
                .get("unsigned")
                .and_then(|unsigned| unsigned.get("agent_authorization_admission"))
                .is_some()
            {
                return Err(event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_proof",
                    "Agent Event proof requires matching independently verified Agent signer evidence",
                ));
            }
            // §5.4/§8.2: `{principal}#{device_id}` resolves from the current
            // device-set projection. DID control/delegation methods resolve
            // from the DID document and retain the high-risk freshness gate.
            // Both branches go through the SDK's **Event proof** verifier, not
            // the generic detached-JWS one: the Event protected-header profile
            // rejects a `kid` member and requires the protected-header
            // algorithm to be Ed25519. Handing hand-built
            // binding bytes to the generic verifier — as this call site used to
            // do — silently dropped both checks.
            if !verify_with_federated_signer_evidence(
                internal_admission,
                session,
                object,
                &verification_method,
                &proof_binding_bytes,
                &jws,
            )? {
                crate::jws_verify::verify_principal_authorized_event_proof_async(
                    &typed_proof,
                    envelope_bytes,
                    &actor_did,
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

fn verify_with_federated_agent_signer_evidence(
    internal_admission: Option<&InternalEventAdmission>,
    session: &SessionRecord,
    object: &serde_json::Map<String, Value>,
    verification_method: &str,
    canonical_bytes: &[u8],
    jws: &str,
) -> Result<bool, EventValidationError> {
    let Some(evidence) = internal_admission.and_then(|admission| {
        admission.agent_signer_evidence(session, object, verification_method)
    }) else {
        return Ok(false);
    };
    let material = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: evidence.public_key().to_vec(),
    };
    // §3 — key material rides in the independently verified federation
    // evidence; zero resolver calls.
    let outcome = arkret_signatures::Ed25519DetachedJwsVerifier::new().verify_detached_jws(
        jws,
        canonical_bytes,
        &material,
    );
    crate::metrics::record_signature_verify(
        crate::metrics::SIGNATURE_SCHEME_FEDERATED_AGENT_EVIDENCE,
        outcome.is_ok(),
    );
    outcome.map_err(|error| {
        tracing::debug!(%error, "federated Agent Event proof JWS verification failed");
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "federated Agent Event proof JWS verification failed",
        )
    })?;
    Ok(true)
}

async fn verify_with_active_agent_session(
    state: &AppState,
    session: &SessionRecord,
    signer_id: &str,
    verification_method: &str,
    canonical_bytes: &[u8],
    jws: &str,
) -> Result<bool, EventValidationError> {
    let Some(agent_session) = session.agent_session.as_ref() else {
        return Ok(false);
    };
    if session.actor != signer_id
        || agent_session.freshness_state != arkret_wire::FreshnessState::Fresh
    {
        return Err(event_validation_error(
            StatusCode::UNAUTHORIZED,
            "invalid_proof",
            "Agent Event proof requires a fresh session for the Event actor",
        ));
    }
    let Some((_, authorization_ref)) = state
        .projections()
        .snapshot()
        .active_agent_key_authorizations(signer_id)
        .into_iter()
        .find(|(key_id, _)| key_id == verification_method)
    else {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "invalid_proof",
            "Agent Event proof verification method is not currently authorized",
        ));
    };
    let authorization = state
        .event_queries()
        .canonical_event(&authorization_ref)
        .await
        .map_err(|error| {
            event_validation_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "auth_unavailable",
                format!("Agent key authorization lookup failed: {error}"),
            )
        })?
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "auth_unavailable",
                "Agent key authorization Event is unavailable",
            )
        })?;
    let payload = authorization
        .envelope
        .get("payload")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "auth_unavailable",
                "Agent key authorization payload is unavailable",
            )
        })?;
    if authorization.kind != arkret_wire::EventKind::AGENT_KEY_AUTHORIZE
        || payload.get("agent_id").and_then(Value::as_str) != Some(signer_id)
        || payload.get("verification_method").and_then(Value::as_str) != Some(verification_method)
    {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "invalid_proof",
            "Agent key authorization does not match the Event signer",
        ));
    }
    let public_key: Value =
        serde_json::from_str(session.session_public_key.as_deref().ok_or_else(|| {
            event_validation_error(
                StatusCode::UNAUTHORIZED,
                "invalid_proof",
                "Agent session omitted its authorized public key",
            )
        })?)
        .map_err(|_| {
            event_validation_error(
                StatusCode::UNAUTHORIZED,
                "invalid_proof",
                "Agent session public key is not valid JSON",
            )
        })?;
    let encoded_key = public_key
        .get("key")
        .or_else(|| public_key.get("x"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::UNAUTHORIZED,
                "invalid_proof",
                "Agent session public key omitted Ed25519 key material",
            )
        })?;
    // Session grants carry the RFC 7638 JWK form, while the durable
    // `ak.agent.key.authorize` binding hashes Arkret's runtime-key form.
    let authorized_public_key = serde_json::json!({
        "kty": "OKP",
        "kid": verification_method,
        "algorithm": "Ed25519",
        "key": encoded_key,
    });
    let public_key_digest = arkret_signatures::agent::agent_runtime_public_key_digest(
        &authorized_public_key,
    )
    .map_err(|_| {
        event_validation_error(
            StatusCode::UNAUTHORIZED,
            "invalid_proof",
            "Agent session public key is invalid",
        )
    })?;
    if payload.get("public_key_digest").and_then(Value::as_str) != Some(public_key_digest.as_str())
    {
        return Err(event_validation_error(
            StatusCode::UNAUTHORIZED,
            "invalid_proof",
            "Agent session public key does not match its active authorization",
        ));
    }
    let key_bytes = URL_SAFE_NO_PAD.decode(encoded_key).map_err(|_| {
        event_validation_error(
            StatusCode::UNAUTHORIZED,
            "invalid_proof",
            "Agent session public key is not valid base64url",
        )
    })?;
    let material = arkret_signatures::PublicKeyMaterial::Ed25519Raw { bytes: key_bytes };
    // §3 — key material comes from the active Agent session grant; zero
    // resolver calls.
    let outcome = arkret_signatures::Ed25519DetachedJwsVerifier::new().verify_detached_jws(
        jws,
        canonical_bytes,
        &material,
    );
    crate::metrics::record_signature_verify(
        crate::metrics::SIGNATURE_SCHEME_AGENT_SESSION,
        outcome.is_ok(),
    );
    outcome.map_err(|_| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "Agent Event proof JWS verification failed",
        )
    })?;
    Ok(true)
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
    // §3 — key material rides in the independently verified federated
    // device-signing evidence; zero resolver calls.
    let outcome = arkret_signatures::Ed25519DetachedJwsVerifier::new().verify_detached_jws(
        jws,
        canonical_bytes,
        &material,
    );
    crate::metrics::record_signature_verify(
        crate::metrics::SIGNATURE_SCHEME_FEDERATED_SIGNER_EVIDENCE,
        outcome.is_ok(),
    );
    outcome.map_err(|error| {
        tracing::debug!(%error, "federated Event proof JWS verification failed");
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "federated Event proof JWS verification failed",
        )
    })?;
    Ok(true)
}

/// Parse the wire proof into the SDK [`arkret_wire::Proof`] and reproduce the
/// canonical proof-binding transcript it must have signed (`encoding.md` §6).
///
/// The typed proof is returned alongside the bytes because the DID-rooted
/// verification path needs the proof itself: the SDK's Event-profile verifier
/// derives the transcript from `(proof, actor_id)` on its own and applies header
/// checks the generic detached-JWS profile does not.
pub(super) fn event_proof_binding_bytes(
    event_digest: &str,
    actor_id: &str,
    verification_method: &str,
    created_at: &str,
    proof_object: &serde_json::Map<String, Value>,
) -> Result<(arkret_wire::Proof, arkret_identifiers::Did, Vec<u8>), EventValidationError> {
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
    let bytes = proof.canonical_binding_bytes(&actor).map_err(|error| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            format!("proof binding canonicalization failed: {error}"),
        )
    })?;
    Ok((proof, actor, bytes))
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use soland_storage_postgres::Db;

    use super::*;

    fn state() -> AppState {
        AppState::new(
            crate::config::AppConfig {
                object_storage: crate::config::ObjectStorageConfig::local(
                    std::env::temp_dir().join("soland-event-proof-root-test"),
                ),
                did_resolver_allow_methods: vec!["key".to_owned()],
                jws_replay_window_seconds: 0,
                ..crate::config::AppConfig::test_default()
            },
            Db { pool: None },
        )
    }

    fn session(actor: &str, state: &AppState) -> SessionRecord {
        let created_at = chrono::Utc::now();
        SessionRecord {
            token_hash: "event-proof-root-test".to_owned(),
            actor: actor.to_owned(),
            device_id: "ak:device:01904100-0000-7000-8000-000000000001".to_owned(),
            audience: state.service_id().clone(),
            session_public_key: None,
            agent_session: None,
            session_grant: None,
            expires_at: created_at + chrono::Duration::minutes(1),
            created_at,
            revoked_at: None,
        }
    }

    /// These fixtures never reach the signature check, so the envelope bytes
    /// only have to be non-empty.
    const ENVELOPE_BYTES: &[u8] = br#"{"kind":"ak.test.event"}"#;

    fn event_with_verification_method(actor: &str, verification_method: &str) -> Value {
        json!({
            "actor_id": actor,
            "proofs": [{
                "kind": "detached_jws",
                "verification_method": verification_method,
                "event_digest": format!("sha256:{}", "1".repeat(64)),
                "created_at": "2026-07-21T08:00:00.000Z",
                "jws": "eyJhbGciOiJFZDI1NTE5In0..signature"
            }]
        })
    }

    /// `did-usage-and-verification.md` §2.2 — a proof `verification_method` is a
    /// DID URL. The bare actor DID names no key at all, so it must be refused
    /// before any signature check; a look-alike root must be refused too.
    #[tokio::test]
    async fn rejects_a_bare_actor_did_as_proof_verification_method() {
        let state = state();
        let actor = "did:key:z6MkfixtureAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let session = session(actor, &state);
        let digest = format!("sha256:{}", "1".repeat(64));

        for verification_method in [
            // bare DID — the exact form the old `!=` disjunct let through
            actor.to_owned(),
            // trailing marker but still no fragment
            format!("{actor}#"),
            // a different root that merely starts with the actor DID
            format!("{actor}.evil#key-1"),
        ] {
            let event = event_with_verification_method(actor, &verification_method);
            let error = validate_event_proofs(
                event.as_object().unwrap(),
                &state,
                &session,
                actor,
                &digest,
                arkret_canonical::DigestSuite::Sha256,
                ENVELOPE_BYTES,
                &[],
                None,
            )
            .await
            .expect_err("proof verification method must be a DID URL rooted in the signer");
            assert_eq!(
                error.status,
                StatusCode::FORBIDDEN,
                "{verification_method}: {}",
                error.message
            );
        }
    }

    /// The positive control: a well-formed `{actor}#{fragment}` gets past the
    /// rooting gate and fails later, on the signature — proving the gate above
    /// rejects for the right reason.
    #[tokio::test]
    async fn accepts_a_rooted_did_url_and_fails_only_on_the_signature() {
        let state = state();
        let actor = "did:key:z6MkfixtureAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let session = session(actor, &state);
        let digest = format!("sha256:{}", "1".repeat(64));
        let event = event_with_verification_method(actor, &format!("{actor}#key-1"));

        let error = validate_event_proofs(
            event.as_object().unwrap(),
            &state,
            &session,
            actor,
            &digest,
            arkret_canonical::DigestSuite::Sha256,
            ENVELOPE_BYTES,
            &[],
            None,
        )
        .await
        .expect_err("the fixture signature is not valid");
        assert_ne!(
            error.status,
            StatusCode::FORBIDDEN,
            "a rooted DID URL must not be rejected by the rooting gate: {}",
            error.message
        );
    }
}
