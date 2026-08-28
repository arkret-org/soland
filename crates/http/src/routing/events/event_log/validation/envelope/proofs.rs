use arkret_event_draft::EventPayloadExt as _;

use super::minimal_metadata_author::{
    minimal_metadata_author_context, validate_minimal_metadata_author_proof,
};
use super::*;
use crate::routing::events::event_log::submit::InternalEventAdmission;

fn root_anchor_event_public_key(
    signer_controller: &str,
) -> Result<arkret_signatures::PublicKeyMaterial, EventValidationError> {
    let multibase = signer_controller.strip_prefix("did:key:").ok_or_else(|| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "root-anchor update authority must use canonical did:key material",
        )
    })?;
    Ok(arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
        value: multibase.to_owned(),
    })
}

fn did_key_from_ed25519_bytes(bytes: &[u8]) -> Result<arkret_wire::DidKey, EventValidationError> {
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "verified Event producer key is not Ed25519",
        )
    })?;
    let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(&bytes);
    arkret_wire::DidKey::new(format!("did:key:{multibase}")).map_err(|error| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            format!("verified Event producer key is invalid: {error}"),
        )
    })
}

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
) -> Result<arkret_wire::DidKey, EventValidationError> {
    let proofs = object
        .get("proofs")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "param_missing",
                "proofs are required",
            )
        })?;
    if proofs.is_empty() {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "param_missing",
            "proofs must contain at least one proof",
        ));
    }
    let producer_proofs = proofs
        .iter()
        .filter(|proof| proof.get("kind").and_then(Value::as_str) == Some("detached_jws"))
        .collect::<Vec<_>>();
    if producer_proofs.len() != 1
        || (proofs.len() != 1 && !(internal_admission.is_some() && proofs.len() == 2))
    {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "Event must carry one producer proof and only federated accepted Events may carry one admission proof",
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
    let typed_identity_anchor_event = if object.get("kind").and_then(Value::as_str)
        == Some(arkret_wire::EventKind::DeviceAuthorize.as_str())
    {
        Some(
            serde_json::from_value::<arkret_wire::Event>(Value::Object(object.clone())).map_err(
                |error| {
                    event_validation_error(
                        StatusCode::BAD_REQUEST,
                        "schema_violation",
                        format!("device authorization must be a typed SDK Event: {error}"),
                    )
                },
            )?,
        )
    } else {
        None
    };
    let typed_candidate = if let Some(event) = typed_identity_anchor_event.as_ref() {
        let payload = event
            .typed_payload::<arkret_wire::event_spec::DeviceAuthorize>()
            .map_err(|error| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    format!("invalid typed ak.device.authorize payload: {error}"),
                )
            })?;
        matches!(
            payload.authorization_binding_kind,
            arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizationBindingKind::RegistrationAnchor
                | arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizationBindingKind::PcrRecovery
        )
        .then_some(payload)
    } else {
        None
    };
    let root_anchored_candidate = typed_candidate.as_ref().and_then(|payload| {
        realm_bootstrap_contexts.iter().find_map(|context| {
            let candidate = context.identity_anchor_candidate_device.as_ref()?;
            (context.actor_id == actor_id
                && candidate.principal_id == payload.principal_id
                && candidate.device_id == payload.device_id
                && candidate.device_public_key_did == payload.device_public_key_did
                && candidate.hpke_key == payload.hpke_key
                && candidate.algorithms == payload.algorithms
                && candidate.authorization_binding_kind == payload.authorization_binding_kind)
                .then(|| {
                    (
                        candidate.clone(),
                        context.identity_anchor_resolution.clone(),
                    )
                })
        })
    });
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
    if let Some(proof) = producer_proofs.into_iter().next() {
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
        if let Some((candidate, staged_resolution)) = root_anchored_candidate.as_ref() {
            let resolution = if let Some(resolution) = staged_resolution.clone() {
                resolution
            } else {
                let resolution = state
                    .projections()
                    .snapshot()
                    .principal_resolution_for_realm(
                        typed_identity_anchor_event
                            .as_ref()
                            .expect("candidate payload came from a typed Event")
                            .realm_id
                            .as_str(),
                    )
                    .cloned()
                    .ok_or_else(|| {
                        event_validation_error(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "stale_did_document",
                            "candidate device Event proof requires the accepted PCR resolution",
                        )
                    })?;
                serde_json::from_value::<arkret_models_identity::ResolutionCommitment>(resolution)
                    .map_err(|error| {
                    event_validation_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "schema_violation",
                        format!("stored PCR resolution is not the public SDK type: {error}"),
                    )
                })?
            };
            if !arkret_wire::project_did_to_core_id(&resolution.did)
                .is_ok_and(|principal| principal.as_str() == actor_id)
            {
                return Err(event_validation_error(
                    StatusCode::FORBIDDEN,
                    "invalid_proof",
                    "candidate device proof resolution does not project to actor_id",
                ));
            }
            let expected_method = format!("{}#{}", resolution.did, candidate.device_id);
            if verification_method_url.as_str() != expected_method {
                return Err(event_validation_error(
                    StatusCode::FORBIDDEN,
                    "invalid_proof",
                    "candidate device Event proof must use initial_resolution.did#device_id",
                ));
            }
        }
        let signer_controller = if root_anchored_candidate.is_some() {
            // key-management.md §5.0.1: the founding/recovery device proof is
            // rooted in the verified resolution DID, not the stable core ID.
            // The exact DID + device fragment was checked above and the
            // candidate overlay below supplies its typed public key. Do not
            // run this proof through the ordinary actor CoreId rooting gate.
            method_root.to_owned()
        } else if minimal_metadata_context.is_some() {
            // Pairwise authorship deliberately does not compare a resolvable
            // did:key controller string with the stable Core DidCoreId here.
            // The closed policy verifier below projects the DID controller
            // and checks it against actor_id before accepting the Leaf key.
            method_root.to_owned()
        } else if let Some(expected_root_method) = root_anchor_method.as_deref() {
            if verification_method_url != expected_root_method {
                return Err(event_validation_error(
                    StatusCode::FORBIDDEN,
                    "invalid_proof",
                    "root-anchored Event proof must use the active update authority from the referenced DID entry",
                ));
            }
            method_root.to_owned()
        } else {
            let method_root = arkret_wire::Did::new(method_root.to_owned())
                .and_then(|did| arkret_wire::project_did_to_core_id(&did));
            let ordinary_proof_root_id = arkret_wire::DidCoreId::new(ordinary_proof_root.clone());
            if method_root.as_ref().ok() != ordinary_proof_root_id.as_ref().ok()
                || method_root.is_err()
                || ordinary_proof_root_id.is_err()
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
            if let Some((candidate, _)) = root_anchored_candidate.as_ref() {
                let multibase = candidate
                    .device_public_key_did
                    .as_str()
                    .strip_prefix("did:key:")
                    .ok_or_else(|| {
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
                return did_key_from_ed25519_bytes(&material.ed25519_bytes().map_err(|error| {
                    event_validation_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_proof",
                        format!("candidate device Event key is invalid: {error}"),
                    )
                })?);
            }
            // account-lifecycle.md §2.1.2: PCR genesis is admitted before a
            // principal grant or device-directory projection exists. Its
            // create Event is authorized by the frozen DID entry's current
            // active update key, which `resolve_event_root_anchor_method`
            // selected and matched against this proof above. Verify that
            // did:key material directly with the strict SDK Event-proof
            // verifier; the ordinary principal-authorized path below requires
            // already-accepted PCR-scoped device evidence and therefore cannot
            // authorize this pre-grant root proof.
            if root_anchor_method.is_some() {
                let material = root_anchor_event_public_key(&signer_controller)?;
                arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
                    &typed_proof,
                    envelope_bytes,
                    &actor_did,
                    &material,
                    digest_suite,
                )
                .map_err(|error| {
                    tracing::debug!(%error, "root-anchor Event proof verification failed");
                    event_validation_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_proof",
                        "root-anchor Event proof verification failed",
                    )
                })?;
                return did_key_from_ed25519_bytes(&material.ed25519_bytes().map_err(|error| {
                    event_validation_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_proof",
                        format!("root-anchor Event key is invalid: {error}"),
                    )
                })?);
            }
            // §2.10.3 minimal-metadata branch: LeafNode trust anchor, pure
            // did:key fragment key material, zero DID-freshness / resolver /
            // principal-directory calls. Mutually exclusive with the
            // DID-document path below.
            if let Some(context) = &minimal_metadata_context {
                return validate_minimal_metadata_author_proof(
                    state,
                    context,
                    object,
                    actor_id,
                    &verification_method,
                    &proof_binding_bytes,
                    &jws,
                )
                .await;
            }
            if internal_admission
                .is_some_and(|admission| admission.is_local_service_producer(session, object))
            {
                let expected_method =
                    state
                        .service_verification_method("notary-key")
                        .map_err(|error| {
                            event_validation_error(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "internal_error",
                                format!(
                                    "local service Event signing method is unavailable: {error}"
                                ),
                            )
                        })?;
                if expected_method.as_str() != verification_method {
                    return Err(event_validation_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_proof",
                        "local service Event proof does not use the local service notary key",
                    ));
                }
                let public_key = state.notary_signing_key().verifying_key();
                let material = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                    bytes: public_key.to_bytes().to_vec(),
                };
                arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
                    &typed_proof,
                    envelope_bytes,
                    &actor_did,
                    &material,
                    digest_suite,
                )
                .map_err(|error| {
                    tracing::debug!(%error, "local service Event proof signature failed");
                    event_validation_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_proof",
                        "local service Event proof signature is invalid",
                    )
                })?;
                return did_key_from_ed25519_bytes(public_key.as_bytes());
            }
            if let Some(signing_key) = internal_admission.and_then(|admission| {
                admission.applet_formal_producer_signing_key(session, object, &verification_method)
            }) {
                let material = root_anchor_event_public_key(signing_key.as_str())?;
                arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
                    &typed_proof,
                    envelope_bytes,
                    &actor_did,
                    &material,
                    digest_suite,
                )
                .map_err(|error| {
                    tracing::debug!(%error, "staged Applet formal Event proof verification failed");
                    event_validation_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_proof",
                        "staged Applet formal Event proof is invalid",
                    )
                })?;
                return Ok(signing_key.clone());
            }
            if let Some(signing_key) = verify_with_installed_applet_registration_epoch(
                state,
                object,
                &typed_proof,
                envelope_bytes,
                &actor_did,
                &signer_controller,
                &verification_method,
                digest_suite,
            )
            .await?
            {
                return Ok(signing_key);
            }
            if let Some(signing_key) = verify_with_active_agent_session(
                state,
                session,
                &signer_controller,
                &verification_method,
                &proof_binding_bytes,
                &jws,
            )
            .await?
            {
                return Ok(signing_key);
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
            // A development login may be either a synthetic local fixture with
            // no PCR/device authority or a real registered principal that used
            // the local login surface. Try the deterministic development key
            // first, but fall through to the ordinary PCR/device verifier when
            // it does not match. SessionGrant-backed and production sessions
            // never enter this branch.
            if state.config().development_mode && session.session_grant.is_none() {
                let device_fragment = verification_method
                    .rsplit_once('#')
                    .map(|(_, fragment)| fragment)
                    .ok_or_else(|| {
                        event_validation_error(
                            StatusCode::BAD_REQUEST,
                            "invalid_proof",
                            "development device Event proof method has no device fragment",
                        )
                    })?;
                arkret_wire::DeviceId::new(device_fragment.to_owned()).map_err(
                    |_| {
                        event_validation_error(
                            StatusCode::BAD_REQUEST,
                            "invalid_proof",
                            "development device Event proof method fragment is not a canonical device id",
                        )
                    },
                )?;
                let signing_key = arkret_signatures::development_signing_key(&verification_method);
                let material = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                    bytes: signing_key.verifying_key().to_bytes().to_vec(),
                };
                let development_verification =
                    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
                        &typed_proof,
                        envelope_bytes,
                        &actor_did,
                        &material,
                        digest_suite,
                    );
                crate::metrics::record_signature_verify(
                    crate::metrics::SIGNATURE_SCHEME_DEVELOPMENT,
                    development_verification.is_ok(),
                );
                if development_verification.is_ok() {
                    return did_key_from_ed25519_bytes(signing_key.verifying_key().as_bytes());
                }
                tracing::debug!(
                    "deterministic development Event key did not match; trying registered device authority"
                );
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
            if let Some(signing_key) = verify_with_federated_signer_evidence(
                internal_admission,
                session,
                object,
                &verification_method,
                &proof_binding_bytes,
                &jws,
            )? {
                return Ok(signing_key);
            } else {
                let verification = if object.get("kind").and_then(Value::as_str)
                    == Some(arkret_wire::EventKind::IdentityResolutionUpdate.as_str())
                {
                    crate::jws_verify::verify_registered_identity_resolution_event_proof_async(
                        &typed_proof,
                        envelope_bytes,
                        &actor_did,
                        &verification_method,
                        &signer_controller,
                        state,
                    )
                    .await
                } else {
                    let device_fragment = verification_method
                        .rsplit_once('#')
                        .map(|(_, fragment)| fragment)
                        .ok_or_else(|| {
                            event_validation_error(
                                StatusCode::BAD_REQUEST,
                                "invalid_proof",
                                "ordinary device Event proof method has no device fragment",
                            )
                        })?;
                    arkret_wire::DeviceId::new(device_fragment.to_owned()).map_err(|_| {
                        event_validation_error(
                            StatusCode::BAD_REQUEST,
                            "invalid_proof",
                            "ordinary device Event proof method fragment is not a canonical device id",
                        )
                    })?;
                    crate::jws_verify::verify_principal_authorized_event_proof_async(
                        &typed_proof,
                        envelope_bytes,
                        &actor_did,
                        &verification_method,
                        &signer_controller,
                        state,
                    )
                    .await
                };
                let signing_key = verification.map_err(|error| {
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
                return Ok(signing_key);
            }
        }
    }
    Err(event_validation_error(
        StatusCode::BAD_REQUEST,
        "invalid_proof",
        "Event has no verified producer key",
    ))
}

#[allow(clippy::too_many_arguments)]
async fn verify_with_installed_applet_registration_epoch(
    state: &AppState,
    object: &serde_json::Map<String, Value>,
    proof: &arkret_wire::ProducerEventProof,
    envelope_bytes: &[u8],
    actor_id: &arkret_wire::DidCoreId,
    signer_controller: &str,
    verification_method: &str,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<Option<arkret_wire::DidKey>, EventValidationError> {
    let Some(applet_id) = object.get("applet_id").and_then(Value::as_str) else {
        return Ok(None);
    };
    let fail = |code: &'static str, message: &'static str| {
        event_validation_error(StatusCode::BAD_REQUEST, code, message)
    };
    let effective_scope: arkret_wire::ScopeRef = serde_json::from_value(
        object
            .get("scope_ref")
            .cloned()
            .ok_or_else(|| fail("schema_violation", "Applet Event proof requires scope_ref"))?,
    )
    .map_err(|_| {
        fail(
            "schema_violation",
            "Applet Event proof scope_ref is invalid",
        )
    })?;
    let effective_scope_key = soland_storage::applet_effective_scope_key(&effective_scope)
        .map_err(|_| {
            fail(
                "schema_violation",
                "Applet Event proof scope_ref is invalid",
            )
        })?;
    let record = state
        .event_queries()
        .applet(applet_id, &effective_scope_key)
        .await
        .map_err(|error| {
            tracing::error!(%error, %applet_id, "failed to read installed Applet proof authority");
            event_validation_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Applet proof authority store is unavailable",
            )
        })?
        .ok_or_else(|| {
            fail(
                "applet_registration_unauthorized",
                "Applet Event proof has no installed registration",
            )
        })?;
    let record: crate::routing::extensions::applet_bridge::AppletRecord =
        serde_json::from_value(record).map_err(|error| {
            tracing::error!(%error, %applet_id, "stored Applet proof authority is invalid");
            event_validation_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "stored Applet proof authority is invalid",
            )
        })?;
    record.validate_stored_bindings().map_err(|error| {
        tracing::error!(%error, %applet_id, "stored Applet proof authority bindings are invalid");
        event_validation_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "stored Applet proof authority bindings are invalid",
        )
    })?;
    if record.revoked_at.is_some()
        || !matches!(record.status.as_str(), "installed" | "partially_installed")
    {
        return Err(fail(
            "applet_revoked",
            "Applet Event proof registration is not active",
        ));
    }
    let package = &record.package;
    if package.service_id.as_str() != signer_controller
        || package.webhook_auth.key_ref.as_str() != verification_method
    {
        return Err(fail(
            "applet_registration_epoch_signing_key_mismatch",
            "Applet Event proof does not use the installed service signing key",
        ));
    }
    let evidence =
        crate::routing::extensions::applet_bridge::registration_epoch_evidence_from_record(&record)
            .map_err(|reason| {
                tracing::error!(%reason, %applet_id, "stored Applet registration Event is invalid");
                event_validation_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "stored Applet registration Event is invalid",
                )
            })?;
    if !evidence.contains_signing_key(verification_method) {
        return Err(fail(
            "applet_registration_epoch_signing_key_mismatch",
            "Applet Event proof key is outside the installed registration epoch",
        ));
    }
    let document =
        crate::jws_verify::resolve_did_document(state, &evidence.did).map_err(|reason| {
            tracing::debug!(%reason, %applet_id, "Applet Event proof DID resolution failed");
            fail(
                "applet_registration_epoch_evidence_mismatch",
                "Applet Event proof DID document could not be resolved",
            )
        })?;
    evidence
        .validate_against_did_document(&document)
        .map_err(|reason| {
            tracing::debug!(%reason, %applet_id, "Applet Event proof epoch evidence mismatch");
            fail(
                "applet_registration_epoch_evidence_mismatch",
                "Applet Event proof registration-epoch evidence is stale or mismatched",
            )
        })?;
    let public_key =
        arkret_identity::jws::resolve_ed25519_pubkey_from_document(&document, verification_method)
            .map_err(|reason| {
                tracing::debug!(%reason, %applet_id, "Applet Event proof key resolution failed");
                fail(
                    "applet_registration_epoch_signing_key_mismatch",
                    "Applet Event proof signing key is unavailable",
                )
            })?;
    let material = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: public_key.to_bytes().to_vec(),
    };
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        envelope_bytes,
        actor_id,
        &material,
        digest_suite,
    )
    .map_err(|error| {
        tracing::debug!(%error, %applet_id, "Applet Event proof signature failed");
        fail("invalid_proof", "Applet Event proof signature is invalid")
    })?;
    did_key_from_ed25519_bytes(public_key.as_bytes()).map(Some)
}

async fn verify_with_active_agent_session(
    state: &AppState,
    session: &SessionRecord,
    signer_id: &str,
    verification_method: &str,
    canonical_bytes: &[u8],
    jws: &str,
) -> Result<Option<arkret_wire::DidKey>, EventValidationError> {
    let Some(agent_session) = session.agent_session.as_ref() else {
        return Ok(None);
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
    let Some(grant) = session.session_grant.as_ref() else {
        return Err(event_validation_error(
            StatusCode::UNAUTHORIZED,
            "invalid_proof",
            "Agent Event proof requires a typed session-grant authority binding",
        ));
    };
    let arkret_models_identity::SessionGrantHolderBinding::AgentRuntime {
        agent_id,
        device_id,
        agent_key_authorization_ref,
        verification_method: granted_verification_method,
    } = &grant.holder_binding
    else {
        return Err(event_validation_error(
            StatusCode::UNAUTHORIZED,
            "invalid_proof",
            "Agent Event proof cannot use a human-device session grant",
        ));
    };
    if agent_id.as_str() != signer_id
        || device_id.as_str() != session.device_id
        || granted_verification_method.as_str() != verification_method
    {
        return Err(event_validation_error(
            StatusCode::UNAUTHORIZED,
            "invalid_proof",
            "Agent Event proof does not match its typed session-grant key binding",
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
    if authorization_ref != agent_key_authorization_ref.as_str() {
        return Err(event_validation_error(
            StatusCode::UNAUTHORIZED,
            "invalid_proof",
            "Agent session grant names a stale key authorization Event",
        ));
    }
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
    if authorization.kind != arkret_wire::EventKind::AgentKeyAuthorize.as_str()
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
    let signing_key = did_key_from_ed25519_bytes(&key_bytes)?;
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
    Ok(Some(signing_key))
}

pub(super) fn verify_with_federated_signer_evidence(
    internal_admission: Option<&InternalEventAdmission>,
    session: &SessionRecord,
    object: &serde_json::Map<String, Value>,
    verification_method: &str,
    canonical_bytes: &[u8],
    jws: &str,
) -> Result<Option<arkret_wire::DidKey>, EventValidationError> {
    let Some(signing_key) = internal_admission.and_then(|admission| {
        admission.federated_producer_signing_key(session, object, verification_method)
    }) else {
        return Ok(None);
    };
    let multibase = signing_key
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
    // The producer key is bound into the independently verified origin
    // Principal Server admission proof; no device-history sidecar is needed.
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
    Ok(Some(signing_key.clone()))
}

/// Parse the wire proof into the SDK [`arkret_wire::ProducerEventProof`] and reproduce the
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
) -> Result<
    (
        arkret_wire::ProducerEventProof,
        arkret_wire::DidCoreId,
        Vec<u8>,
    ),
    EventValidationError,
> {
    let proof: arkret_wire::ProducerEventProof =
        serde_json::from_value(Value::Object(proof_object.clone())).map_err(|error| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_proof",
                format!("event proof is not an SDK ProducerEventProof: {error}"),
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
    let actor = arkret_wire::DidCoreId::new(actor_id.to_owned()).map_err(|error| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            format!("event actor_id is not a valid Core DidCoreId: {error}"),
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

    fn signed_service_franking_event(
        state: &AppState,
    ) -> (arkret_wire::AuthoredEvent, SessionRecord, String, String) {
        let realm_id = "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K".to_owned();
        let target_event_id = "ak:event:AQsHmGu_9sPOyJ4aG8VlWQBp8wGGhdC-BjfAaXqrIbk-".to_owned();
        let actor_id = arkret_wire::DidCoreId::new(state.service_id().clone()).unwrap();
        let service_did = state.service_resolution_commitment().did.clone();
        let verification_method = state.service_verification_method("notary-key").unwrap();
        let created_at = chrono::Utc::now();
        let event = arkret_wire::test_support::raw_event_at(
            arkret_wire::EventKind::ModerationFrankingProof.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: arkret_wire::RealmId::new(realm_id.clone()).unwrap(),
            },
            actor_id.clone(),
            actor_id.clone(),
            0,
            arkret_wire::Hlc::new("019041000000-0000-00000000".to_owned()).unwrap(),
            json!({
                "realm_id": realm_id,
                "event_id": target_event_id,
                "received_by": actor_id,
                "verification_method": verification_method,
                "received_at": "2026-08-28T00:00:00.000Z",
                "replay_nonce": "0123456789abcdef",
                "signature": "c2lnbmF0dXJl"
            }),
            created_at,
        )
        .unwrap();
        let mut event = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
            event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        let signer = arkret_signatures::Ed25519PayloadSigner::new(
            state.notary_signing_key().as_ref().clone(),
            service_did,
            verification_method.clone(),
        );
        arkret_signatures::sign_event(
            &mut event,
            &signer,
            &verification_method,
            arkret_signatures::SignEventOptions::new().with_created_at(created_at),
        )
        .unwrap();
        let session = SessionRecord {
            token_hash: "franking-proof-service-test".to_owned(),
            actor: state.service_id().clone(),
            device_id: String::new(),
            audience: state.service_id().clone(),
            session_public_key: None,
            agent_session: None,
            session_grant: None,
            expires_at: created_at + chrono::Duration::minutes(1),
            created_at,
            revoked_at: None,
        };
        (event, session, realm_id, target_event_id)
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

    #[test]
    fn root_anchor_event_uses_the_frozen_did_key_material() {
        let key = "z6MkfixtureAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let material = root_anchor_event_public_key(&format!("did:key:{key}"))
            .expect("a frozen did:key update authority is valid root material");
        assert!(matches!(
            material,
            arkret_signatures::PublicKeyMaterial::Ed25519Multibase { value } if value == key
        ));
        assert!(root_anchor_event_public_key("did:webvh:fixture.example").is_err());
    }

    /// `did-usage-and-verification.md` §2.2 — a proof `verification_method` is a
    /// DID URL. The bare actor DID names no key at all, so it must be refused
    /// before any signature check; a look-alike root must be refused too.
    #[tokio::test]
    async fn rejects_a_bare_actor_did_as_proof_verification_method() {
        let state = state();
        let signer = "did:webvh:z6mkfixture:alice.example";
        let actor = crate::test_actor_id_str(signer).to_string();
        let session = session(&actor, &state);
        let digest = format!("sha256:{}", "1".repeat(64));

        for verification_method in [
            // DID without a fragment — the exact form the old `!=` disjunct let through
            signer.to_owned(),
            // trailing marker but still no fragment
            format!("{signer}#"),
            // a different webvh SCID, so it projects to a different core identity
            "did:webvh:z6mkevil:alice.example#key-1".to_owned(),
        ] {
            let mut event = event_with_verification_method(&actor, &verification_method);
            event["executed_by"] = json!(actor);
            let error = validate_event_proofs(
                event.as_object().unwrap(),
                &state,
                &session,
                &actor,
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
        let signer = "did:webvh:z6mkfixture:alice.example";
        let actor = crate::test_actor_id_str(signer).to_string();
        let session = session(&actor, &state);
        let digest = format!("sha256:{}", "1".repeat(64));
        let mut event = event_with_verification_method(&actor, &format!("{signer}#key-1"));
        event["executed_by"] = json!(actor);

        let error = validate_event_proofs(
            event.as_object().unwrap(),
            &state,
            &session,
            &actor,
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

    /// `event-and-patch.md` sections 2.4 and 3.1 plus
    /// `content-moderation.md` section 3.4: a receiving service directly
    /// authors the durable franking-proof Event as its own service principal.
    /// Its producer proof therefore resolves through the exact local service
    /// DID method, never through the development-device proof branch.
    #[tokio::test]
    async fn accepts_exactly_bound_service_franking_event_producer_proof() {
        let state = state();
        let (event, session, realm_id, target_event_id) = signed_service_franking_event(&state);
        let envelope_bytes =
            arkret_canonical::canonical_json_bytes(&event.event().digest_payload().unwrap())
                .unwrap();
        let event_digest = event.event().proofs[0]
            .as_producer()
            .unwrap()
            .event_digest
            .to_string();
        let object = serde_json::to_value(event.event()).unwrap();
        let object = object.as_object().unwrap();
        let admission = InternalEventAdmission::service_franking_proof(
            &realm_id,
            state.service_id().as_str(),
            &target_event_id,
        );

        validate_event_proofs(
            object,
            &state,
            &session,
            state.service_id().as_str(),
            &event_digest,
            arkret_canonical::DigestSuite::Sha256,
            &envelope_bytes,
            &[],
            Some(&admission),
        )
        .await
        .expect("an exactly bound service-authored franking Event must verify with the notary key");
    }

    #[tokio::test]
    async fn service_franking_producer_branch_rejects_a_different_target_binding() {
        let state = state();
        let (event, session, realm_id, _) = signed_service_franking_event(&state);
        let envelope_bytes =
            arkret_canonical::canonical_json_bytes(&event.event().digest_payload().unwrap())
                .unwrap();
        let event_digest = event.event().proofs[0]
            .as_producer()
            .unwrap()
            .event_digest
            .to_string();
        let object = serde_json::to_value(event.event()).unwrap();
        let object = object.as_object().unwrap();
        let admission = InternalEventAdmission::service_franking_proof(
            &realm_id,
            state.service_id().as_str(),
            "ak:event:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );

        let error = validate_event_proofs(
            object,
            &state,
            &session,
            state.service_id().as_str(),
            &event_digest,
            arkret_canonical::DigestSuite::Sha256,
            &envelope_bytes,
            &[],
            Some(&admission),
        )
        .await
        .expect_err("a service admission for another target must not authorize the producer key");
        assert_eq!(error.code, "invalid_proof");
    }
}
