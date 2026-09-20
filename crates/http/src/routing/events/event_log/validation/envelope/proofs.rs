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

async fn verify_with_historical_signer_evidence(
    state: &AppState,
    event: &arkret_wire::Event,
    proof: &arkret_wire::ProducerEventProof,
    envelope_bytes: &[u8],
    event_actor: &arkret_wire::ActorId,
    signer: &arkret_wire::ActorId,
) -> Result<arkret_wire::DidKey, EventValidationError> {
    let evidence_ref = proof
        .signer_resolution_evidence_ref
        .as_ref()
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_proof",
                "ordinary Event producer proof must reference signer evidence",
            )
        })?;
    let content_digest = evidence_ref.content_digest().map_err(|error| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            format!("producer signer evidence reference is invalid: {error}"),
        )
    })?;
    let selector = arkret_models_collaboration::governance_dependencies::GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
        content_digest,
    };
    let dependency = state
        .persistence()
        .governance_dependency_store()
        .get_unscoped_signer_evidence(&selector)
        .await
        .map_err(|error| {
            event_validation_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "auth_unavailable",
                format!("producer signer evidence lookup failed: {error}"),
            )
        })?;
    let dependency = dependency.ok_or_else(|| {
        event_validation_error(
            StatusCode::CONFLICT,
            "dependency_missing",
            "ordinary Event historical producer source is unavailable",
        )
    })?;
    let arkret_models_collaboration::governance_dependencies::GovernanceDependency::AuthenticatedSignerResolutionEvidence {
        authenticated_signer_resolution_evidence: evidence,
        ..
    } = dependency
    else {
        return Err(event_validation_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "schema_violation",
            "producer signer evidence selector resolved to the wrong dependency kind",
        ));
    };
    if evidence.signer_id() != signer.signing_principal_id() {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "invalid_proof",
            "producer signer evidence does not bind the Event signer",
        ));
    }
    if evidence.verification_method() != &proof.verification_method {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "invalid_proof",
            "producer signer evidence does not bind the selected verification method",
        ));
    }
    let public_key = if matches!(
        evidence.as_ref(),
        arkret_models_identity::AuthenticatedSignerResolutionEvidence::Agent { .. }
    ) {
        crate::routing::identity::agents::evidence::verified_historical_agent_event_key(
            state, event, &evidence,
        )
        .await
        .map_err(|error| event_validation_error(StatusCode::BAD_REQUEST, "invalid_proof", error))?
    } else {
        *crate::routing::events::event_log::submit::verify_historical_producer(
            state,
            event,
            proof.event_digest.digest_suite().map_err(|error| {
                event_validation_error(StatusCode::BAD_REQUEST, "invalid_proof", error.to_string())
            })?,
        )
        .await
        .map_err(|error| {
            let missing = error.starts_with("dependency_missing:");
            event_validation_error(
                if missing {
                    StatusCode::CONFLICT
                } else {
                    StatusCode::BAD_REQUEST
                },
                if missing {
                    "dependency_missing"
                } else {
                    "invalid_proof"
                },
                error,
            )
        })?
        .key()
    };
    let material = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: public_key.to_vec(),
    };
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        envelope_bytes,
        event_actor,
        &material,
        proof.event_digest.digest_suite().map_err(|error| {
            event_validation_error(StatusCode::BAD_REQUEST, "invalid_proof", error.to_string())
        })?,
    )
    .map_err(|error| {
        tracing::debug!(%error, "historical producer Event proof verification failed");
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "producer Event proof signature is invalid",
        )
    })?;
    did_key_from_ed25519_bytes(&public_key)
}

pub(crate) async fn validate_event_proofs(
    object: &serde_json::Map<String, Value>,
    state: &AppState,
    session: &SessionRecord,
    actor_id: &str,
    expected_payload_digest: &str,
    digest_suite: arkret_canonical::DigestSuite,
    // The Event's canonical bytes with `producer_proof` / `unsigned` stripped — exactly
    // what `expected_payload_digest` was computed over. The SDK Event-proof
    // verifier re-derives `event_digest` from these and constant-time compares
    // it to `proof.event_digest`, so the transcript the signature covers is
    // never reconstructed by hand at this call site.
    envelope_bytes: &[u8],
    realm_bootstrap_contexts: &[RealmBootstrapBatchContext],
    internal_admission: Option<&InternalEventAdmission>,
) -> Result<arkret_wire::DidKey, EventValidationError> {
    let event_actor = serde_json::from_value::<arkret_wire::ActorId>(
        object.get("actor_id").cloned().ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "param_missing",
                "actor_id is required",
            )
        })?,
    )
    .map_err(|error| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            format!("event actor_id is invalid: {error}"),
        )
    })?;
    let proof = object.get("producer_proof").ok_or_else(|| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "param_missing",
            "producer_proof is required",
        )
    })?;
    let proofs = std::slice::from_ref(proof);
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
    let typed_identity_anchor_event = if matches!(
        object.get("kind").and_then(Value::as_str),
        Some(kind)
            if kind == arkret_wire::EventKind::DeviceReanchor.as_str()
                || kind == arkret_wire::EventKind::DeviceAuthorize.as_str()
    ) {
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
    let typed_candidate = if typed_identity_anchor_event
        .as_ref()
        .is_some_and(|event| event.kind == arkret_wire::EventKind::DeviceAuthorize)
    {
        let event = typed_identity_anchor_event
            .as_ref()
            .expect("candidate branch requires a typed identity-anchor Event");
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
    let root_anchored_candidate = realm_bootstrap_contexts.iter().find_map(|context| {
        let candidate = context.identity_anchor_candidate_device.as_ref()?;
        if context.actor_id != event_actor.to_string() {
            return None;
        }
        let event = typed_identity_anchor_event.as_ref()?;
        let matches_anchor = event.kind == arkret_wire::EventKind::DeviceReanchor
            && context.identity_anchor_event_id.as_deref() == Some(event.event_id.as_str())
            && candidate.authorization_binding_kind
                == arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizationBindingKind::PcrRecovery;
        let matches_authorize = typed_candidate.as_ref().is_some_and(|payload| {
            candidate.device_id == payload.device_id
                && candidate.device_public_key_did == payload.device_public_key_did
                && candidate.hpke_key == payload.hpke_key
                && candidate.algorithms == payload.algorithms
                && candidate.authorization_binding_kind == payload.authorization_binding_kind
        });
        (matches_anchor || matches_authorize).then(|| {
            (
                candidate.clone(),
                context.identity_anchor_resolution.clone(),
            )
        })
    });
    let ordinary_proof_root = object
        .get("executed_by")
        .map(|value| serde_json::from_value::<arkret_wire::ActorId>(value.clone()))
        .transpose()
        .map_err(|_| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "executed_by must be a full ActorId",
            )
        })?
        .unwrap_or_else(|| event_actor.clone())
        .signing_principal_id()
        .to_string();
    let root_anchor_method = resolve_event_root_anchor_method(state, object, actor_id).await?;
    // §2.10.3 — minimal-metadata content Events authenticate authorship
    // against the active MLS LeafNode at the envelope's `(group_id, epoch,
    // group_state_ref)` instead of the DID-document / directory path. The
    // context is only `Some` when the Realm positively declared the
    // minimal-metadata profile AND the payload carries an encrypted-content
    // envelope.
    let minimal_metadata_context = minimal_metadata_author_context(object, state).await;
    if let Some(proof) = proofs.first() {
        let Some(proof_object) = proof.as_object() else {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_proof",
                "event producer_proof must be a JSON object",
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
                let projection = serde_json::from_value::<
                    arkret_models_identity::PrincipalResolutionProjection,
                >(resolution)
                .map_err(|error| {
                    event_validation_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "schema_violation",
                        format!("stored PCR resolution is not the public SDK type: {error}"),
                    )
                })?;
                arkret_models_identity::ResolutionCommitment {
                    did: projection.did,
                    method_history_head: projection.method_history_head,
                    version_id: projection.version_id,
                }
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
                &event_actor,
                &verification_method,
                &created_at,
                proof_object,
            )?;
            let signer = object
                .get("executed_by")
                .cloned()
                .map(serde_json::from_value::<arkret_wire::ActorId>)
                .transpose()
                .map_err(|error| {
                    event_validation_error(
                        StatusCode::BAD_REQUEST,
                        "schema_violation",
                        format!("executed_by is invalid: {error}"),
                    )
                })?
                .unwrap_or_else(|| event_actor.clone());
            let typed_event =
                serde_json::from_value::<arkret_wire::Event>(Value::Object(object.clone()))
                    .map_err(|error| {
                        event_validation_error(
                            StatusCode::BAD_REQUEST,
                            "schema_violation",
                            format!("producer Event is invalid: {error}"),
                        )
                    })?;
            let staged_applet_key = internal_admission.and_then(|admission| {
                admission.applet_formal_producer_signing_key(session, object, &verification_method)
            });
            if root_anchored_candidate.is_none()
                && root_anchor_method.is_none()
                && minimal_metadata_context.is_none()
                && staged_applet_key.is_none()
            {
                return verify_with_historical_signer_evidence(
                    state,
                    &typed_event,
                    &typed_proof,
                    envelope_bytes,
                    &event_actor,
                    &signer,
                )
                .await;
            }
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
            if let Some(signing_key) = staged_applet_key {
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
        }
    }
    Err(event_validation_error(
        StatusCode::BAD_REQUEST,
        "invalid_proof",
        "Event has no verified producer key",
    ))
}

pub(super) fn event_proof_binding_bytes(
    event_digest: &str,
    actor_id: &arkret_wire::ActorId,
    verification_method: &str,
    created_at: &str,
    proof_object: &serde_json::Map<String, Value>,
) -> Result<
    (
        arkret_wire::ProducerEventProof,
        arkret_wire::ActorId,
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
    let bytes = proof.canonical_binding_bytes(actor_id).map_err(|error| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            format!("proof binding canonicalization failed: {error}"),
        )
    })?;
    Ok((proof, actor_id.clone(), bytes))
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
            account_pk: None,
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
        let event = arkret_wire::test_support::raw_event_for_actor_at(
            arkret_wire::EventKind::ModerationFrankingProof.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: arkret_wire::RealmId::new(realm_id.clone()).unwrap(),
            },
            arkret_wire::ActorId::service(actor_id.clone()),
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
            arkret_signatures::SignEventOptions::new(
                arkret_wire::SignerEvidenceRef::new(format!(
                    "ak:signer_evidence:sha256:{}",
                    "11".repeat(32)
                ))
                .unwrap(),
            )
            .with_created_at(created_at),
        )
        .unwrap();
        let session = SessionRecord {
            account_pk: None,
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
            "actor_id": arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new(actor).unwrap(), crate::test_event::station_id(),
            )),
            "producer_proof": {
                "kind": "detached_jws",
                "verification_method": verification_method,
                "event_digest": format!("sha256:{}", "1".repeat(64)),
                "created_at": "2026-07-21T08:00:00.000Z",
                "jws": "eyJhbGciOiJFZDI1NTE5In0..signature"
            }
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
            event["executed_by"] = event["actor_id"].clone();
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
    /// Its exact producer source must still be available and authenticated;
    /// an internal business marker cannot substitute the local notary key.
    #[tokio::test]
    async fn internal_service_admission_cannot_replace_missing_historical_source() {
        let state = state();
        let (event, session, realm_id, target_event_id) = signed_service_franking_event(&state);
        let envelope_bytes =
            arkret_canonical::canonical_json_bytes(&event.event().digest_payload().unwrap())
                .unwrap();
        let event_digest = event
            .event()
            .producer_proof
            .as_ref()
            .expect("producer proof")
            .event_digest
            .to_string();
        let object = serde_json::to_value(event.event()).unwrap();
        let object = object.as_object().unwrap();
        let admission = InternalEventAdmission::service_franking_proof(
            &realm_id,
            event.event().actor_id.clone(),
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
        .expect_err("an internal service marker cannot replace authenticated source evidence");
    }
}
