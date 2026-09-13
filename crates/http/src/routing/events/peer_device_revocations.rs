use arkret_wire::{
    AcceptedDevicePossessionProof, DeviceRevocationGateActionClass,
    DeviceRevocationGateCheckOutcome, DeviceRevocationGateCheckRequestBody,
    DeviceRevocationGateDecision, DeviceRevocationGateDecisionReceipt, Hash, SealId,
};
use salvo::prelude::*;
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};
use soland_services::ServiceErrorKind;

use super::peer::{cross_domain_replay, schema_violation};
use crate::state::AppState;

/// Admit the origin-derived selector, or classify why it could not be derived.
///
/// The derivation-domain section of `device-lifecycle.md` makes this a two-way split,
/// never a three-way one:
///
/// * the derivation is a partial function — an unknown device, a device that belongs to another
///   account, a never-authorized device and an authorization that is no longer current all leave it
///   undefined. On this authenticated peer surface every one of them MUST collapse into the same
///   anti-enumeration `authority_mismatch` receipt, so the caller cannot tell them apart. That is
///   expressed here as `Ok(None)`.
/// * a projection row that claims current / active / verified while omitting its schema-required
///   authorization Event id or generation ref is a projection integrity failure, not an ordinary
///   "unauthorized" answer. It MUST surface as an internal availability fault and MUST NOT be
///   returned as `allow`.
fn admit_origin_current_selector(
    derived: Result<soland_storage::DeviceRevocationGateSelector, soland_services::ServiceError>,
) -> Result<Option<soland_storage::DeviceRevocationGateSelector>, AppError> {
    match derived {
        Ok(selector) => Ok(Some(selector)),
        Err(error) if matches!(error.kind(), ServiceErrorKind::NotFound) => Ok(None),
        Err(error) => Err(AppError::internal(format!(
            "origin device authorization projection is unavailable: {error}"
        ))),
    }
}

/// The receipt members a linearized gate status projects to, before typed-id
/// parsing.
struct GateDecisionProjection {
    decision: DeviceRevocationGateDecision,
    derived_binding: Option<(String, u64)>,
    blocking_proposal_digest: Option<String>,
    covering_seal_id: Option<String>,
}

/// `service-http-binding.md` §`ak.peer.device_revocations.command.check.v1` —
/// only `allow` carries the origin-derived selector. Every other decision,
/// `authority_mismatch` included, MUST return no `derived_binding` so the
/// receipt cannot be read as an oracle for "does this device exist".
fn project_gate_decision(
    status: soland_storage::DeviceRevocationGateStatus,
    origin_current_selector: Option<&soland_storage::DeviceRevocationGateSelector>,
) -> GateDecisionProjection {
    let plain = |decision| GateDecisionProjection {
        decision,
        derived_binding: None,
        blocking_proposal_digest: None,
        covering_seal_id: None,
    };
    match status {
        soland_storage::DeviceRevocationGateStatus::Active => GateDecisionProjection {
            decision: DeviceRevocationGateDecision::Allow,
            derived_binding: origin_current_selector.map(|selector| {
                (
                    selector.target_device_authorize_event_id.clone(),
                    selector.target_device_generation_ref,
                )
            }),
            blocking_proposal_digest: None,
            covering_seal_id: None,
        },
        soland_storage::DeviceRevocationGateStatus::Pending {
            blocking_proposal_digest,
        } => GateDecisionProjection {
            blocking_proposal_digest: Some(blocking_proposal_digest),
            ..plain(DeviceRevocationGateDecision::RevocationPending)
        },
        soland_storage::DeviceRevocationGateStatus::Revoked { covering_seal_id } => {
            GateDecisionProjection {
                covering_seal_id: Some(covering_seal_id),
                ..plain(DeviceRevocationGateDecision::Revoked)
            }
        }
        soland_storage::DeviceRevocationGateStatus::AuthorityMismatch => {
            plain(DeviceRevocationGateDecision::AuthorityMismatch)
        }
        soland_storage::DeviceRevocationGateStatus::GenerationMismatch => {
            plain(DeviceRevocationGateDecision::GenerationMismatch)
        }
    }
}

fn current_binding_stable(
    before: Option<&soland_storage::DeviceRevocationGateSelector>,
    after: Option<&soland_storage::DeviceRevocationGateSelector>,
) -> bool {
    before == after
}

fn accepted_device_proof_requires_verification(
    origin_current_selector: Option<&soland_storage::DeviceRevocationGateSelector>,
) -> bool {
    // Device authorization derivation is a partial function. An unknown,
    // foreign, or never-authorized device must reach this authenticated peer
    // surface as the same `authority_mismatch` decision, not fail while
    // resolving the proof key and become an account/device enumeration oracle.
    origin_current_selector.is_some()
}

#[salvo::oapi::endpoint(
    operation_id = "ak.peer.device_revocations.command.check",
    tags("events")
)]
#[tracing::instrument(skip_all, fields(op = "ak.peer.device_revocations.command.check.v1"))]
pub(super) async fn check_device_revocation_gate(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DeviceRevocationGateCheckOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");

    // Authentication precedes every principal/device lookup. A caller must not
    // use this operation as an account oracle.
    //
    // `service-http-binding.md` §2.2.3 registers this operation on the
    // deployment-internal authenticated channel, and the only admitted caller
    // relationship is "the Account Authority bound to this exact account → this
    // origin Station". There is no external calling branch: a request that did
    // not arrive over that registered channel is rejected here, before any
    // device-private state is read, and there is no fallback to a service
    // signature, to a self-reported `Source-Service-ID`, or to an anonymous
    // call. When no channel is registered the operation fails closed.
    //
    // Every plaintext proxy on the channel is part of the trusted deployment
    // TCB, which is why the receipt below has no detached proof or
    // `verification_method` and neither direction signs the transport shell.
    crate::routing::events::peer::authenticate_internal_channel_request(
        state,
        req,
        arkret_wire::ServiceOperationId::PEER_DEVICE_REVOCATIONS_COMMAND_CHECK_V1,
    )
    .await?;

    let request = req
        .parse_json::<DeviceRevocationGateCheckRequestBody>()
        .await
        .map_err(|_| {
            AppError::json_invalid(
                "invalid ak.peer.device_revocations.command.check.v1 request body",
            )
        })?;
    request
        .validate()
        .map_err(|error| schema_violation(error.to_string()))?;
    if !matches!(
        request.action_class,
        DeviceRevocationGateActionClass::SessionGrantIssue
            | DeviceRevocationGateActionClass::ReturningSessionGrantIssue
            | DeviceRevocationGateActionClass::SessionGrantRefresh
    ) {
        return Err(schema_violation(
            "peer device revocation check only admits session grant issue or refresh",
        ));
    }

    // The target Station is the local fixed-route receiver, not an identity
    // repeated in channel headers.
    if request.account_id.station_id != state.service_core_id() {
        return Err(cross_domain_replay(
            "device revocation gate request is routed to the wrong Station",
        ));
    }

    // Identity-anchor admission uses the same principal-scoped lock. Holding it
    // through proof verification and receipt construction keeps the memory
    // adapter linearizable and avoids needless optimistic retries in one
    // process. PostgreSQL correctness does not rely on this process-local lock:
    // the durable gate is followed by an exact current-binding revalidation.
    let generation_lock =
        crate::routing::identity::device_generation::device_generation_admission_lock(
            request.account_id.principal_id.as_str(),
        );
    let _generation_guard = generation_lock.lock().await;

    let origin_current_selector = admit_origin_current_selector(
        crate::routing::identity::device_generation::active_device_revocation_gate_selector(
            state,
            request.account_id.principal_id.as_str(),
            request.device_id.as_str(),
        )
        .await,
    )?;

    // A handoff/session DPoP proves possession of the short-lived holder key,
    // not of the durable accepted-device key. Returning issue and human
    // refresh therefore carry one closed proof, verified here against the
    // origin's accepted current device authority before any allow receipt can
    // be minted. Initial registration/recovery issue deliberately has no such
    // proof because its accepted binding comes from its own terminal ledger.
    let accepted_device_possession_proof_digest = request
        .accepted_device_possession_proof
        .as_ref()
        .map(AcceptedDevicePossessionProof::proof_digest)
        .transpose()
        .map_err(|error| schema_violation(error.to_string()))?;
    let verified_proof_binding = if let Some(proof) = request
        .accepted_device_possession_proof
        .as_ref()
        .filter(|_| accepted_device_proof_requires_verification(origin_current_selector.as_ref()))
    {
        let (issued_at, expires_at, signature) = match proof {
            AcceptedDevicePossessionProof::Issue(proof) => {
                (proof.issued_at, proof.expires_at, proof.signature.as_str())
            }
            AcceptedDevicePossessionProof::Refresh(proof) => {
                (proof.issued_at, proof.expires_at, proof.signature.as_str())
            }
        };
        let now = chrono::Utc::now();
        if request.requested_at < issued_at
            || request.requested_at >= expires_at
            || now < issued_at
            || now >= expires_at
        {
            return Err(schema_violation(
                "accepted-device possession proof is outside its validity window",
            ));
        }
        let signing_bytes = proof
            .canonical_signing_bytes()
            .map_err(|error| schema_violation(error.to_string()))?;
        let verified_binding = crate::jws_verify::verify_principal_authorized_ed25519_signature_with_account_authority_async(
            &signing_bytes,
            signature,
            proof.verification_method().as_str(),
            &request.account_id,
            &request.device_id,
            state,
        )
        .await
        .map_err(|error| {
            tracing::warn!(
                %error,
                principal_id = %request.account_id.principal_id,
                device_id = %request.device_id,
                "accepted-device possession proof verification failed"
            );
            schema_violation("accepted-device possession proof is invalid")
        })?;
        Some(verified_binding)
    } else {
        None
    };
    if let Some(verified_binding) = verified_proof_binding
        && !origin_current_selector.as_ref().is_some_and(|selector| {
            selector.target_device_authorize_event_id
                == verified_binding.authorization_event_id.as_str()
                && selector.target_device_generation_ref == verified_binding.generation_ref
        })
    {
        return Err(schema_violation(
            "accepted-device proof key is no longer the current device generation",
        ));
    }
    let action_class = match request.action_class {
        DeviceRevocationGateActionClass::SessionGrantIssue => {
            soland_storage::DeviceRevocationGateAction::SessionGrantIssue
        }
        DeviceRevocationGateActionClass::ReturningSessionGrantIssue => {
            soland_storage::DeviceRevocationGateAction::SessionGrantIssue
        }
        DeviceRevocationGateActionClass::SessionGrantRefresh => {
            soland_storage::DeviceRevocationGateAction::SessionGrantRefresh
        }
        _ => unreachable!("non-session action rejected above"),
    };
    let linearization = state
        .persistence()
        .linearize_device_revocation_gate(
            soland_storage::DeviceRevocationGateLinearizationRequest {
                principal_id: request.account_id.principal_id.clone(),
                station_id: request.account_id.station_id.clone(),
                device_id: request.device_id.to_string(),
                expected_device_authorize_event_id: request
                    .expected_device_authorize_event_id
                    .as_ref()
                    .map(ToString::to_string),
                expected_device_generation_ref: request.expected_device_generation_ref,
                origin_current_selector: origin_current_selector.clone(),
                action_class,
                intent_digest: request.intent_digest.to_string(),
                requested_at: request.requested_at,
            },
        )
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "device revocation gate linearization failed: {error}"
            ))
        })?;

    // Optimistic current-device linearization. Revocation acceptance is
    // already ordered with this intent by the durable per-device gate head.
    // Re-read the independently projected authorization/generation after that
    // durable point and require the exact content-addressed Event + monotonic
    // generation snapshot observed during proof verification. A generation
    // or key transition that committed before the gate is rejected here; one
    // that commits afterwards is correctly ordered after this decision.
    let post_linearization_selector = admit_origin_current_selector(
        crate::routing::identity::device_generation::active_device_revocation_gate_selector(
            state,
            request.account_id.principal_id.as_str(),
            request.device_id.as_str(),
        )
        .await,
    )?;
    if !current_binding_stable(
        origin_current_selector.as_ref(),
        post_linearization_selector.as_ref(),
    ) {
        return Err(AppError::conflict(
            "device authorization changed while the gate decision was linearized",
        )
        .with_internal_reason("device_generation_changed"));
    }

    let GateDecisionProjection {
        decision,
        derived_binding,
        blocking_proposal_digest,
        covering_seal_id,
    } = project_gate_decision(
        linearization.status.clone(),
        origin_current_selector.as_ref(),
    );
    let blocking_proposal_digest = blocking_proposal_digest
        .map(|digest| {
            Hash::new(digest).map_err(|error| {
                AppError::internal(format!(
                    "stored blocking proposal digest is invalid: {error}"
                ))
            })
        })
        .transpose()?;
    let covering_seal_id = covering_seal_id
        .map(|seal_id| {
            SealId::new(seal_id).map_err(|error| {
                AppError::internal(format!("stored covering Seal id is invalid: {error}"))
            })
        })
        .transpose()?;
    let (target_device_authorize_event_id, target_device_generation_ref) = match derived_binding {
        Some((event_id, generation)) => (
            Some(arkret_wire::EventId::new(event_id).map_err(|error| {
                AppError::internal(format!(
                    "derived device authorization Event id is invalid: {error}"
                ))
            })?),
            Some(generation),
        ),
        None => (None, None),
    };
    // `device-lifecycle.md` §2.2 / `service-http-binding.md` §2.2.3: the receipt
    // is delivered only on the registered deployment-internal channel between
    // the Account Authority bound to this exact account and this origin Station,
    // and that channel — not a detached signature — carries its authenticity and
    // integrity. The receipt is therefore closed: it MUST NOT carry `proof` or
    // `verification_method`, so nothing here reads a signing key or mints a JWS.
    // The durable decision record written above is untouched: it still binds the
    // immutable `intent_digest` for exact replay, and the receipt still carries
    // the accepted-device possession proof digest, the 30s `expires_at` fence,
    // the `linearization_seq`, the complete AccountId and the origin-derived
    // selector under the closed decision rules.
    let receipt = DeviceRevocationGateDecisionReceipt {
        account_id: request.account_id.clone(),
        device_id: request.device_id.clone(),
        target_device_authorize_event_id,
        target_device_generation_ref,
        action_class: request.action_class,
        intent_digest: request.intent_digest.clone(),
        accepted_device_possession_proof_digest,
        decision,
        linearization_seq: linearization.linearization_seq,
        linearized_at: linearization.linearized_at,
        expires_at: linearization.expires_at,
        blocking_proposal_digest,
        covering_seal_id,
    };
    let outcome = DeviceRevocationGateCheckOutcome {
        decision_receipt: receipt,
    };
    outcome
        .validate_for_request(&request)
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(outcome)
}

#[cfg(test)]
mod tests {
    use soland_services::ServiceError;
    use soland_storage::{DeviceRevocationGateSelector, DeviceRevocationGateStatus};

    use super::*;

    const PRINCIPAL: &str = "ak:did_core:webvh:z6mkfixture:alice.example";
    const STATION: &str = "ak:did_core:web:soland.example";
    const DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000000030";
    const AUTHORIZE_EVENT: &str = "ak:event:ATyaOl1JkDDCC-6ZytsgoAKvlQJ6s6NJuDC_bmWKARBa";

    fn selector() -> DeviceRevocationGateSelector {
        DeviceRevocationGateSelector {
            principal_id: arkret_wire::DidCoreId::new(PRINCIPAL).unwrap(),
            station_id: arkret_wire::DidCoreId::new(STATION).unwrap(),
            device_id: DEVICE.to_owned(),
            target_device_authorize_event_id: AUTHORIZE_EVENT.to_owned(),
            target_device_generation_ref: 1,
        }
    }

    fn allow_receipt() -> DeviceRevocationGateDecisionReceipt {
        let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        DeviceRevocationGateDecisionReceipt {
            account_id: arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new(PRINCIPAL).unwrap(),
                arkret_wire::DidCoreId::new(STATION).unwrap(),
            ),
            device_id: arkret_wire::DeviceId::new(DEVICE).unwrap(),
            target_device_authorize_event_id: Some(
                arkret_wire::EventId::new(AUTHORIZE_EVENT).unwrap(),
            ),
            target_device_generation_ref: Some(1),
            action_class: DeviceRevocationGateActionClass::SessionGrantRefresh,
            intent_digest: Hash::new(format!("sha256:{}", "c".repeat(64))).unwrap(),
            accepted_device_possession_proof_digest: Some(
                Hash::new(format!("sha256:{}", "d".repeat(64))).unwrap(),
            ),
            decision: DeviceRevocationGateDecision::Allow,
            linearization_seq: 9,
            linearized_at: now,
            expires_at: now + chrono::Duration::seconds(30),
            blocking_proposal_digest: None,
            covering_seal_id: None,
        }
    }

    /// `device-lifecycle.md` §2.2 closes this receipt in both directions: the
    /// deployment-internal channel of `service-http-binding.md` §2.2.3 carries
    /// its authenticity, so the emitted receipt carries neither `proof` nor
    /// `verification_method`, and a receipt that presents either member is
    /// rejected whole rather than verified "if present".
    #[test]
    fn decision_receipt_is_closed_against_detached_proof_members() {
        let receipt = allow_receipt();
        let encoded = serde_json::to_value(&receipt).expect("receipt serializes");
        let members = encoded.as_object().expect("receipt is a JSON object");
        assert!(!members.contains_key("proof"));
        assert!(!members.contains_key("verification_method"));
        // The intent binding, the accepted-device proof digest, the 30s fence
        // and the origin-derived selector are all still on the receipt: this
        // ruling pruned the detached signature, not the decision content.
        assert!(members.contains_key("intent_digest"));
        assert!(members.contains_key("accepted_device_possession_proof_digest"));
        assert!(members.contains_key("linearization_seq"));
        assert!(members.contains_key("expires_at"));
        assert!(members.contains_key("target_device_authorize_event_id"));

        for member in ["proof", "verification_method"] {
            let mut forged = encoded.clone();
            forged[member] = serde_json::json!({
                "kind": "detached_jws",
                "verification_method": "did:web:soland.example#notary-key",
            });
            assert!(
                serde_json::from_value::<DeviceRevocationGateDecisionReceipt>(forged).is_err(),
                "a receipt carrying `{member}` must be rejected whole"
            );
        }
    }

    #[test]
    fn optimistic_linearization_rejects_any_current_binding_change() {
        let before = selector();
        let mut different_generation = before.clone();
        different_generation.target_device_generation_ref += 1;
        let mut different_authorization = before.clone();
        different_authorization.target_device_authorize_event_id =
            format!("ak:event:A{}", "b".repeat(43));

        assert!(current_binding_stable(Some(&before), Some(&before)));
        assert!(current_binding_stable(None, None));
        assert!(!current_binding_stable(
            Some(&before),
            Some(&different_generation)
        ));
        assert!(!current_binding_stable(
            Some(&before),
            Some(&different_authorization)
        ));
        assert!(!current_binding_stable(Some(&before), None));
    }

    /// Canonical positive: a fully derivable selector is admitted and flows
    /// into the `allow` receipt as the origin-derived binding.
    #[test]
    fn derivable_selector_is_admitted_and_only_allow_carries_it() {
        let admitted =
            admit_origin_current_selector(Ok(selector())).expect("derivable selector is admitted");
        assert!(admitted.is_some());

        let projected =
            project_gate_decision(DeviceRevocationGateStatus::Active, admitted.as_ref());
        assert_eq!(projected.decision, DeviceRevocationGateDecision::Allow);
        assert_eq!(
            projected.derived_binding,
            Some((AUTHORIZE_EVENT.to_owned(), 1))
        );
        assert!(accepted_device_proof_requires_verification(
            admitted.as_ref()
        ));
    }

    /// An unknown / never-authorized / foreign device leaves the derivation
    /// undefined (`NotFound`). On this authenticated peer surface that is the
    /// anti-enumeration case: an `authority_mismatch` receipt with no derived
    /// binding and no revocation evidence, never an HTTP error that would
    /// distinguish the four causes.
    #[test]
    fn undefined_derivation_becomes_a_bindingless_authority_mismatch() {
        let admitted = admit_origin_current_selector(Err(ServiceError::NotFound(
            "device authorization is unavailable".to_owned(),
        )))
        .expect("an undefined derivation is not an error on the peer surface");
        assert!(admitted.is_none());

        let projected = project_gate_decision(
            DeviceRevocationGateStatus::AuthorityMismatch,
            admitted.as_ref(),
        );
        assert_eq!(
            projected.decision,
            DeviceRevocationGateDecision::AuthorityMismatch
        );
        assert!(projected.derived_binding.is_none());
        assert!(projected.blocking_proposal_digest.is_none());
        assert!(projected.covering_seal_id.is_none());
        assert!(!accepted_device_proof_requires_verification(None));
    }

    /// A projection row that claims verified / current but omits its
    /// schema-required authorization Event id or generation ref is a projection
    /// integrity failure. It MUST become an internal availability fault, and it
    /// MUST NOT be laundered into the `authority_mismatch` receipt.
    ///
    /// The receipt itself is closed (no `proof`, no `verification_method`), so
    /// this is the only remaining way an unusable projection could have been
    /// published as a decision.
    #[test]
    fn malformed_verified_projection_is_an_internal_fault_not_a_decision() {
        let error = admit_origin_current_selector(Err(ServiceError::SchemaViolation(
            "device authorization omits its accepted Event id".to_owned(),
        )))
        .expect_err("a projection integrity failure must not be signed as a decision");
        assert_eq!(error.code, arkret_wire::ErrorCode::InternalError);
    }

    /// No non-allow decision may leak the origin-derived selector, even when
    /// the selector itself was derivable.
    #[test]
    fn non_allow_decisions_never_carry_the_derived_binding() {
        let selector = selector();
        let cases = [
            (
                DeviceRevocationGateStatus::Pending {
                    blocking_proposal_digest: format!("sha256:{}", "a".repeat(64)),
                },
                DeviceRevocationGateDecision::RevocationPending,
            ),
            (
                DeviceRevocationGateStatus::Revoked {
                    covering_seal_id: "ak:seal:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml"
                        .to_owned(),
                },
                DeviceRevocationGateDecision::Revoked,
            ),
            (
                DeviceRevocationGateStatus::GenerationMismatch,
                DeviceRevocationGateDecision::GenerationMismatch,
            ),
            (
                DeviceRevocationGateStatus::AuthorityMismatch,
                DeviceRevocationGateDecision::AuthorityMismatch,
            ),
        ];
        for (status, expected) in cases {
            let projected = project_gate_decision(status, Some(&selector));
            assert_eq!(projected.decision, expected);
            assert!(
                projected.derived_binding.is_none(),
                "{expected:?} must not carry the origin-derived selector"
            );
        }
    }
}
