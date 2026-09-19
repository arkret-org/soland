use super::*;
use crate::routing::events::event_log::submit::InternalEventAdmission;

#[cfg(test)]
pub(crate) fn validate_event_envelope<'a>(
    state: &'a AppState,
    session: &'a SessionRecord,
    envelope: &'a Value,
) -> std::pin::Pin<
    Box<
        dyn std::future::Future<Output = Result<ValidatedEventEnvelope, EventValidationError>>
            + Send
            + 'a,
    >,
> {
    validate_event_envelope_with_context(state, session, envelope, &[], None)
}

fn validate_canonical_mls_group_id(
    group_id: &str,
    scope: &arkret_wire::ScopeRef,
) -> Result<(), EventValidationError> {
    let expected = scope.canonical_mls_group_id().map_err(|_| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            arkret_wire::ErrorCode::SCHEMA_VIOLATION,
            "MLS effective_scope cannot identify a canonical group",
        )
    })?;
    if group_id != expected.as_str() {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            arkret_wire::ErrorCode::SCHEMA_VIOLATION,
            "MLS group id does not match the canonical effective_scope-derived id",
        ));
    }
    Ok(())
}

fn invalid_typed_mls_payload(error: serde_json::Error) -> EventValidationError {
    event_validation_error(
        StatusCode::BAD_REQUEST,
        arkret_wire::ErrorCode::SCHEMA_VIOLATION,
        format!("MLS payload violates its closed SDK type: {error}"),
    )
}

pub(crate) fn validate_event_envelope_with_context<'a>(
    state: &'a AppState,
    session: &'a SessionRecord,
    envelope: &'a Value,
    realm_bootstrap_contexts: &'a [RealmBootstrapBatchContext],
    internal_admission: Option<&'a InternalEventAdmission>,
) -> std::pin::Pin<
    Box<
        dyn std::future::Future<Output = Result<ValidatedEventEnvelope, EventValidationError>>
            + Send
            + 'a,
    >,
> {
    Box::pin(validate_event_envelope_with_ingress(
        state,
        session,
        envelope,
        realm_bootstrap_contexts,
        internal_admission,
    ))
}

/// Authenticate the private notification without consulting Realm authority.
pub(in crate::routing) async fn validate_private_invite_envelope(
    state: &AppState,
    session: &SessionRecord,
    envelope: &Value,
) -> Result<ValidatedEventEnvelope, EventValidationError> {
    let event: arkret_wire::Event = serde_json::from_value(envelope.clone()).map_err(|error| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            error.to_string(),
        )
    })?;
    let object = envelope.as_object().expect("typed Event is an object");
    if event.kind != arkret_wire::EventKind::InviteCreate
        || event.actor_id.signing_principal_id().as_str() != session.actor
        || !invite_create_actor_is_inviter(object, &session.actor)
    {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            arkret_wire::ErrorCode::SIGNATURE_INVALID,
            "invite producer binding mismatch",
        ));
    }
    let schema_id = event_requirements_schema_id(state, object)?;
    validate_event_schema_and_payload(state, event.kind.as_str(), &schema_id, envelope, object)?;
    validate_event_time_fields(state, object)?;
    let digest_suite = arkret::signed_event_digest_claim(&event)
        .and_then(|digest| digest.digest_suite().map_err(Into::into))
        .map_err(|error| {
            event_validation_error(
                StatusCode::UNAUTHORIZED,
                arkret_wire::ErrorCode::SIGNATURE_INVALID,
                error.to_string(),
            )
        })?;
    let canonical_bytes = event_canonical_bytes(envelope)?;
    let canonical_digest = event_digest_for_suite(&canonical_bytes, digest_suite.as_str())?;
    validate_prelookup_event_identity(
        event.event_id.as_str(),
        &canonical_digest,
        &canonical_bytes,
    )?;
    validate_content_bound_event_id(envelope, digest_suite)?;
    let (_, key) = crate::routing::events::event_log::submit::verify_federated_event_admission(
        state,
        &event,
        digest_suite,
    )
    .await
    .map_err(|error| {
        event_validation_error(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::SIGNATURE_INVALID,
            error,
        )
    })?;
    Ok(ValidatedEventEnvelope {
        event_id: event.event_id,
        actor_id: event.actor_id.signing_principal_id().clone(),
        actor: event.actor_id,
        device_id: None,
        actor_seq: event.actor_seq,
        realm_id: event.realm_id,
        kind: event.kind.as_str().to_owned(),
        schema_id,
        prev_refs: event.prev_refs,
        canonical_digest,
        digest_suite,
        canonical_bytes,
        producer_signing_key: Some(key),
    })
}

/// Spec `zh/models/event-and-patch.md` section 2.5.1 bound (a).
///
/// `created_at` MUST NOT precede the greatest `created_at` among the accepted
/// Events named in `prev_refs`. `prev_refs` is the causal frontier, so every
/// Event in it precedes this one and `max` is the right aggregate; taking the
/// max also removes the ambiguity when `actor_seq - 1` holds a sibling fork,
/// because the producer had to name the whole observed frontier.
///
/// The comparison is signed-value against signed-value and uses no local
/// clock, so every receiver reaches the same verdict in any arrival order.
/// An unknown `prev_ref` is not this check's business — dependency resolution
/// owns that — so a missing record is skipped rather than failed here.
async fn validate_created_at_causal_lower_bound(
    state: &AppState,
    object: &serde_json::Map<String, Value>,
    prev_refs: &[EventId],
) -> Result<(), EventValidationError> {
    let Some(created_at) = object
        .get("created_at")
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
    else {
        return Ok(());
    };
    for prev_ref in prev_refs {
        let Ok(Some(record)) = state
            .event_queries()
            .canonical_event(prev_ref.as_str())
            .await
        else {
            continue;
        };
        let Some(predecessor) = record
            .envelope
            .get("created_at")
            .and_then(Value::as_str)
            .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        else {
            continue;
        };
        if created_at < predecessor {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                arkret_wire::ErrorCode::SchemaViolation.as_str(),
                "created_at_before_causal_predecessor: created_at precedes an Event named in                  prev_refs",
            ));
        }
    }
    Ok(())
}

/// Read-only preparation preflight. This cannot produce an admission token or
/// enter the submit pipeline: the signed Event is validated again on submit.
pub(in crate::routing) async fn validate_message_authoring_candidate(
    state: &AppState,
    event: &Event,
    suite: arkret_canonical::DigestSuite,
) -> Result<(), AppError> {
    let render = |error: EventValidationError| {
        let mut result = AppError::from_rejection(
            ErrorCode::from_wire(error.code).unwrap_or(ErrorCode::PolicyViolation),
            error.message,
        );
        if let Some(reason) = error.reason_code {
            result = result.with_reason_code(reason);
        }
        result
    };
    if event.kind != arkret_wire::EventKind::MessageCreate || !event.proofs.is_empty() {
        return Err(crate::app_error!(
            SchemaViolation,
            "expected unsigned Message candidate",
        ));
    }
    let value = serde_json::to_value(event).map_err(|e| AppError::internal(e.to_string()))?;
    let object = value
        .as_object()
        .ok_or_else(|| AppError::internal("Event is not an object"))?;
    validate_created_at_causal_lower_bound(state, object, &event.prev_refs)
        .await
        .map_err(render)?;
    let cells = derived_ordinary_event_cells(&value, object, suite).map_err(render)?;
    realm_authority_root::validate_realm_authority_root_authorization(
        state,
        object,
        event.kind.as_str(),
        event.realm_id.as_str(),
        &event.actor_id,
        false,
        &[],
    )
    .await
    .map_err(render)?;
    let root = event
        .authorization_ref
        .as_ref()
        .is_some_and(|r| r.as_str() == arkret_wire::REALM_AUTHORITY_ROOT_CELL);
    validate_ordinary_event_capability_refs(
        state,
        event.actor_id.signing_principal_id().as_str(),
        state.service_id(),
        event.realm_id.as_str(),
        event.kind.as_str(),
        object,
        &cells,
        root,
        false,
    )
    .await
    .map_err(render)?;
    let operation_id =
        super::super::super::sdk_projection::event_operation_id(&value, event.event_id.as_str())
            .ok_or_else(|| AppError::internal("cannot derive operation identity"))?;
    let operation = arkret_event_draft::ProjectedEventOperation::from_accepted_event(
        operation_id,
        arkret_wire::OperationKind::Create,
        None,
        event,
        suite,
    )
    .map_err(|e| crate::app_error!(SchemaViolation, e.to_string()))?;
    let operations = std::slice::from_ref(&operation);
    validate_operation_semantics(state, operations)
        .map_err(|reason| crate::app_error!(SchemaViolation, reason))?;
    for result in [
        validate_operation_policy(state, operations).await,
        validate_content_encryption_floor(state, operations).await,
    ] {
        result.map_err(|reason| {
            AppError::from_rejection(
                ErrorCode::from_wire(reason).unwrap_or(ErrorCode::FailedPrecondition),
                reason,
            )
        })?;
    }
    Ok(())
}

async fn validate_event_envelope_with_ingress(
    state: &AppState,
    session: &SessionRecord,
    envelope: &Value,
    realm_bootstrap_contexts: &[RealmBootstrapBatchContext],
    internal_admission: Option<&InternalEventAdmission>,
) -> Result<ValidatedEventEnvelope, EventValidationError> {
    let object = envelope.as_object().ok_or_else(|| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_event_envelope",
            "Event Envelope must be a JSON object",
        )
    })?;
    let session_actor_id = arkret_wire::DidCoreId::new(session.actor.clone()).map_err(|error| {
        event_validation_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            format!("session actor is invalid: {error}"),
        )
    })?;
    let session_actor = if internal_admission.is_some() {
        // These closed lanes independently verify the signed full Actor and
        // exact internal admission context; a remote peer is not a local Account.
        object
            .get("actor_id")
            .cloned()
            .and_then(|value| serde_json::from_value::<arkret_wire::ActorId>(value).ok())
            .ok_or_else(|| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    "internal Event requires a full ActorId",
                )
            })?
    } else {
        crate::routing::identity::session_actor::session_actor_from_credential(state, session)
            .map_err(|error| {
                event_validation_error(StatusCode::UNAUTHORIZED, "unauthenticated", error.message)
            })?
    };
    validate_event_critical_features(state, object)?;
    // `effective_scope` is reducer output and is intentionally absent from
    // the closed SDK Event DTO. Reject it from the raw envelope before
    // canonical decoding so callers receive the contract-specific reason
    // instead of a generic unknown-field error.
    if object.get("effective_scope").is_some() {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            arkret_wire::ReasonCode::EFFECTIVE_SCOPE_REDUCER_MANAGED,
            "envelope.effective_scope is reducer-managed; clients MUST NOT supply it",
        ));
    }

    let event_id = event_string_field(object, &["event_id"]).ok_or_else(|| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "param_missing",
            "event_id is required",
        )
    })?;
    let event_id = EventId::new(event_id).map_err(|_| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "param_invalid",
            "event_id must use the ak:event: typed prefix",
        )
    })?;

    let kind = event_string_field(object, &["kind"]).ok_or_else(|| {
        event_validation_error(StatusCode::BAD_REQUEST, "param_missing", "kind is required")
    })?;
    // Receipt objects are not durable Event kinds. Plaintext transient kinds
    // are absent from the active registry and fail the registry gate below;
    // transient product payloads travel encrypted inside Signal.
    if let Some((code, reason)) = events_submit_pre_admit_check(&kind) {
        return Err(event_validation_error(
            error_http_status(code),
            code.as_str(),
            reason,
        ));
    }
    if !artifacts::active_local_operation_event_kinds().contains(&kind) {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "unknown_event_kind",
            "event kind is not in the active registry",
        ));
    }

    let schema_id = event_requirements_schema_id(state, object)?;

    let actor = object.get("actor_id").cloned().ok_or_else(|| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "param_missing",
            "actor_id is required",
        )
    })?;
    let actor = serde_json::from_value::<arkret_wire::ActorId>(actor).map_err(|_| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "param_invalid",
            "actor_id must be a complete ActorId",
        )
    })?;
    let actor_id = actor.signing_principal_id().clone();
    let station_id = actor.route_service_id().clone();
    let actor_seq = object
        .get("actor_seq")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "param_missing",
                "actor_seq is required",
            )
        })?;
    validate_event_time_fields(state, object)?;
    let realm_id = RealmId::new(event_realm_id(object)?).map_err(|_| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "param_invalid",
            "realm_id must be a typed RealmId",
        )
    })?;

    // Identity verification is deliberately the last purely local gate before
    // any admission lookup. Ordinary Realm traffic takes the suite from the
    // trusted Realm projection (or the signed Realm-create payload). A private
    // invite recipient intentionally has no shared-Realm projection, so its
    // first-contact verifier recovers the active suite code carried by the
    // self-describing EventId. The subsequent digest and content-bound-id
    // checks still prove that the complete canonical Event matches that id.
    let canonical_bytes = event_canonical_bytes(envelope)?;
    let digest_suite = event_digest_suite(
        state,
        &kind,
        realm_id.as_str(),
        object,
        realm_bootstrap_contexts,
    )
    .await?;
    let canonical_digest = event_digest_for_suite(&canonical_bytes, &digest_suite)?;
    validate_prelookup_event_identity(event_id.as_str(), &canonical_digest, &canonical_bytes)?;
    let typed_digest_suite = arkret_canonical::digest_suite(&digest_suite)
        .map_err(|_| unsupported_digest_algorithm_error(&digest_suite))?;
    validate_content_bound_event_id(envelope, typed_digest_suite)?;

    // A closed internal adapter can carry an already authenticated Event into
    // this pipeline without a local bearer session. The Event remains authored
    // by its exact producer; `InternalEventAdmission::matches` binds the
    // request-local carrier to the session actor/device, Event actor, Realm,
    // kind and adapter-specific evidence. Resolve that binding before the
    // generic actor/session equality gate below.
    let is_authorized_internal_adapter =
        internal_admission.is_some_and(|admission| admission.matches(session, object));
    let is_applet_managed_pcr_genesis = kind == "ak.realm.create"
        && object
            .get("payload")
            .and_then(Value::as_object)
            .and_then(|payload| payload.get("object"))
            .and_then(Value::as_object)
            .and_then(|genesis| genesis.get("purpose"))
            .and_then(Value::as_str)
            == Some("applet_managed_control");
    let is_verified_applet_formal_aggregate = internal_admission
        .filter(|admission| admission.matches(session, object))
        .is_some_and(InternalEventAdmission::is_applet_formal);
    if is_applet_managed_pcr_genesis && !is_verified_applet_formal_aggregate {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "applet_managed_pcr_genesis_requires_closed_aggregate",
            "Applet-managed PCR genesis is accepted only inside the verified formal install/provision aggregate",
        ));
    }
    let ephemeral_pairwise_author = if actor_id != session_actor_id
        && !is_authorized_internal_adapter
    {
        let context =
            super::minimal_metadata_author::minimal_metadata_author_context(object, state).await;
        super::minimal_metadata_author::is_ephemeral_pairwise_author(
            actor_id.as_str(),
            context.as_ref(),
        )
    } else {
        false
    };
    let agent_delegation = if actor_id != session_actor_id
        && !is_authorized_internal_adapter
        && !ephemeral_pairwise_author
    {
        match crate::routing::identity::agent_pcr::validate_delegated_agent_envelope(
            state,
            object,
            &session.actor,
        )
        .await
        {
            Ok(()) => true,
            Err(error) => {
                tracing::warn!(
                    %actor_id,
                    session_actor = %session.actor,
                    error_code = %error.code,
                    error_message = %error.message,
                    "delegated Agent Event validation failed"
                );
                false
            }
        }
    } else {
        false
    };
    if actor_id != session_actor_id
        && !agent_delegation
        && !is_authorized_internal_adapter
        && !ephemeral_pairwise_author
    {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "actor_session_mismatch",
            "event actor_id must match the bearer session actor",
        ));
    }

    // AKP-0008 / AKP-0009 — when `executed_by` is present the reducer MUST
    // verify the DID resolved from `proof.verification_method` matches
    // `executed_by` (signs-as-X-on-behalf-of-Y attribution proof). This
    // check uses the FIRST proof's verification_method as the proxy for
    // the resolver-derived DID; deep DID-document resolution can replace
    // the prefix match once the agent runtime authorization plumbing
    // lands.
    if let Some(executed_by) = event_string_field(object, &["executed_by"]) {
        let executed_by = arkret_wire::DidCoreId::new(executed_by).map_err(|_| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "param_invalid",
                "executed_by must be a Core DidCoreId",
            )
        })?;
        let proofs = object
            .get("proofs")
            .and_then(Value::as_array)
            .and_then(|arr| arr.first())
            .and_then(Value::as_object);
        let vm = proofs.and_then(|proof| event_string_field(proof, &["verification_method"]));
        let vm_actor = vm
            .as_deref()
            .and_then(|raw| raw.rsplit_once('#').map(|(did, _)| did))
            .and_then(|did| arkret_wire::Did::new(did.to_owned()).ok())
            .and_then(|did| arkret_wire::project_did_to_core_id(&did).ok());
        if vm_actor.as_ref() != Some(&executed_by) {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "executed_by_mismatch",
                "envelope.executed_by must match the DID derived from proof.verification_method",
            ));
        }
    }

    let is_applet_delegated = object.get("applet_id").is_some();
    // `applet-integration.md` §11 scopes the delegated-agent field triple to the
    // Event whose "envelope signature is issued by an applet / delegated agent
    // key while actor_id points at a native principal DID (i.e. actor_id != the
    // signing key's DID)". An applet service signing as itself — the
    // `ak.identity.accountability_grant` of §9.1 has `actor_id=service_id` — is
    // not delegated, and §10.1 requires that Event to carry no `executed_by`.
    // Triggering on `applet_id` alone would demand `executed_by` on exactly the
    // Event the provisioning binding forbids it on. The registration gate
    // (installed, unrevoked, bound to this Realm) still runs either way.
    let producer_signs_as_actor = object
        .get("proofs")
        .and_then(Value::as_array)
        .and_then(|proofs| proofs.first())
        .and_then(Value::as_object)
        .and_then(|proof| event_string_field(proof, &["verification_method"]))
        .and_then(|vm| vm.rsplit_once('#').map(|(did, _)| did.to_owned()))
        .and_then(|did| arkret_wire::Did::new(did).ok())
        .and_then(|did| arkret_wire::project_did_to_core_id(&did).ok())
        .is_some_and(|signer| signer.as_str() == actor_id.as_str());
    // The closed applet provisioning adapter has already verified the installed
    // registration, ghost namespace and provision request before constructing
    // this exact signed Event. Its first formal profile Event is authorized by
    // the accountability-grant Event persisted immediately before it, rather
    // than by an `ak:grant:*` capability object in the runtime grant index.
    let managed_actor = if is_authorized_internal_adapter {
        false
    } else {
        validate_applet_managed_actor_liveness(
            state,
            object,
            actor_id.as_str(),
            &kind,
            realm_id.as_str(),
        )
        .await?
    };
    if !is_authorized_internal_adapter && !managed_actor {
        validate_applet_delegated_authorization_chain(
            state,
            object,
            &kind,
            actor_id.as_str(),
            realm_id.as_str(),
            !producer_signs_as_actor,
        )
        .await?;
    }
    // Round R2/R3 (T07) + Stream-F (Wave 1B) — Realm in terminal state
    // (`ak.realm.tombstone` OR `ak.realm.destroy` applied) refuses every
    // non-audit-class write. Spec `realm-and-space.md` §2.5 / §2.5.1.
    // The projection lock is poison-free (`parking_lot::Mutex`), so this check is
    // always evaluated — a terminal Realm can never be written to because a
    // lock failure defaulted the answer to "not terminal" (fail-open).
    let realm_terminal = state
        .projections()
        .snapshot()
        .realm_is_in_terminal_state(realm_id.as_str());
    if let Some((code, reason)) = terminal_realm_check(realm_terminal, &kind) {
        return Err(event_validation_error(
            error_http_status(code),
            code.as_str(),
            reason,
        ));
    }
    let is_direct_conversation_founding = realm_bootstrap_contexts
        .iter()
        .any(|context| context.direct_conversation_founding);
    let is_realm_bootstrap_followup = is_direct_conversation_founding
        || (is_realm_bootstrap_followup_kind(&kind)
            && realm_bootstrap_contexts.iter().any(|context| {
                context.realm_id == realm_id.as_str() && context.actor_id == actor.to_string()
            }));
    let is_identity_anchor_authorize = kind == arkret_wire::EventKind::DeviceAuthorize.as_str()
        && realm_bootstrap_contexts.iter().any(|context| {
            context.realm_id == realm_id.as_str()
                && context.actor_id == actor.to_string()
                && context
                    .identity_anchor_event_id
                    .as_deref()
                    .is_some_and(|anchor| {
                        object
                            .get("prev_refs")
                            .and_then(Value::as_array)
                            .is_some_and(|refs| refs.len() == 1 && refs[0].as_str() == Some(anchor))
                    })
        });
    let is_identity_anchor_reanchor = kind == arkret_wire::EventKind::DeviceReanchor.as_str()
        && realm_bootstrap_contexts.iter().any(|context| {
            context.realm_id == realm_id.as_str()
                && context.actor_id == actor.to_string()
                && context.identity_anchor_event_id.as_deref() == Some(event_id.as_str())
        });
    // A closed founding unit is checked before its Realm exists. Only its
    // staged follow-ups may use the initial facet values; an accepted frozen
    // or archived cell still blocks even if the ordinary index is absent.
    let staged_creation = !realm_exists_in_index(state, realm_id.as_str())
        && realm_bootstrap_contexts
            .iter()
            .any(|context| context.realm_id == realm_id.as_str())
        && (is_realm_bootstrap_followup || is_identity_anchor_authorize);
    let realm_frozen = {
        let projection = state.projections().snapshot();
        projection.realm_is_archived(realm_id.as_str())
            || projection.realm_is_frozen(realm_id.as_str())
            || (!staged_creation && projection.realm_ordinary_writes_blocked(realm_id.as_str()))
    };
    if let Some(reason) = frozen_realm_check(
        realm_frozen && kind != arkret_wire::EventKind::RealmCreate.as_str(),
        &kind,
        object.get("payload").unwrap_or(&Value::Null),
    ) {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            arkret_wire::ErrorCode::REALM_FROZEN,
            reason,
        ));
    }
    // Spec realm-and-space.md §2.5 — `ak.realm.create` is the genesis
    // event for both the Realm metadata cell AND the creator's first
    // member-state cell. The reducer MUST treat `created_by`
    // as already-a-member when admitting this event; otherwise spec-
    // correct clients can never bootstrap a Realm through the canonical
    // event-submission path. The submit_event commit path (below)
    // materialises the member set in state.realms immediately after
    // store.put succeeds, so any follow-up facet event in the same
    // session naturally passes the regular realm_has_member check.
    let realm_exists = realm_exists_in_index(state, realm_id.as_str());
    // A Agent PCR create is initially published through the batch
    // surface, then may be replayed through the single-submission surface to
    // recover its stored Control Proposal Ack. Let an already accepted Event id
    // reach the submitter's canonical-byte duplicate check; only a different
    // create for the existing Realm is a `realm_already_exists` conflict here.
    let historical_realm_create =
        if kind == arkret_wire::EventKind::RealmCreate.as_str() && realm_exists {
            state
                .event_queries()
                .canonical_event(event_id.as_str())
                .await
                .map_err(|error| {
                    event_validation_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        format!("canonical Event duplicate lookup failed: {error}"),
                    )
                })?
                .is_some()
        } else {
            false
        };
    if kind == arkret_wire::EventKind::RealmCreate.as_str()
        && realm_exists
        && !historical_realm_create
    {
        return Err(event_validation_error(
            StatusCode::CONFLICT,
            "realm_already_exists",
            "realm already exists",
        ));
    }
    if kind == arkret_wire::EventKind::DirectConversationBound.as_str()
        || object.get("authorization_ref").and_then(Value::as_str)
            == Some(arkret_wire::AuthoritySourceId::DIRECT_CONVERSATION_BOOTSTRAP_PARTICIPANT_V1)
    {
        let founding = state
            .event_queries()
            .projected_events_for_realm(realm_id.as_str())
            .await
            .map_err(|_| {
                event_validation_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "founding unit lookup failed",
                )
            })?
            .into_iter()
            .find(|event| event.event_kind == arkret_wire::EventKind::RealmCreate)
            .ok_or_else(|| {
                event_validation_error(
                    StatusCode::FORBIDDEN,
                    "capability_denied",
                    "accepted founding unit is missing",
                )
            })?;
        let refs: Vec<_> = object
            .get("refs")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|reference| {
                reference.get("role").and_then(Value::as_str)
                    == Some("direct_conversation_founding_unit")
            })
            .collect();
        if refs.len() != 1
            || refs[0].get("id").and_then(Value::as_str) != Some(founding.event_id.as_str())
            || refs[0].get("critical").and_then(Value::as_bool) == Some(false)
        {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "capability_denied",
                "binding requires its exact critical founding unit reference",
            ));
        }
        if kind != arkret_wire::EventKind::DirectConversationBound.as_str() {
            let accepted = state
                .event_queries()
                .accepted_event(&founding.event_id)
                .await
                .map_err(|_| {
                    event_validation_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "temporarily_unavailable",
                        "founder lookup failed",
                    )
                })?
                .ok_or_else(|| {
                    event_validation_error(
                        StatusCode::FORBIDDEN,
                        "capability_denied",
                        "accepted founder missing",
                    )
                })?;
            let create: arkret_wire::Event =
                serde_json::from_value(accepted.envelope).map_err(|_| {
                    event_validation_error(
                        StatusCode::FORBIDDEN,
                        "capability_denied",
                        "accepted founder invalid",
                    )
                })?;
            if create.actor_id != session_actor
                || state
                    .contacts()
                    .settled_direct_binding_for_realm(realm_id.as_str())
                    .is_some()
                || !matches!(
                    arkret_wire::EventKind::from(kind.as_str()),
                    arkret_wire::EventKind::MlsProposal
                        | arkret_wire::EventKind::MlsCommit
                        | arkret_wire::EventKind::MlsWelcome
                        | arkret_wire::EventKind::MessageCreate
                )
            {
                return Err(event_validation_error(
                    StatusCode::FORBIDDEN,
                    "capability_denied",
                    "bootstrap authority phase does not permit this author or action",
                ));
            }
        }
    }
    let is_realm_create_bootstrap = kind == arkret_wire::EventKind::RealmCreate.as_str()
        && realm_create_actor_is_creator(object, actor_id.as_str())
        && (actor_id == session_actor_id || agent_delegation)
        && (!realm_exists || historical_realm_create);
    let is_invite_acceptance_join =
        member_join_accepts_pending_invite(state, object, &session_actor, realm_id.as_str()).await;
    let is_invitee_invite_cancel =
        invitee_cancels_pending_invite(state, object, &session_actor, realm_id.as_str()).await;
    let is_third_party_invite_claim = invite_claim_actor_claims_pending_third_party_invite(
        state,
        object,
        &session_actor,
        realm_id.as_str(),
    )
    .await;
    // join-policy.md §7.1 — a not-yet-member applicant MUST be able to submit
    // their own `ak.member.state{membership=knock}` (and the profile-private
    // application sub-payload it carries). Gate / review enforcement happens at
    // the later `join` transition, not on the knock itself.
    let is_member_self_knock = member_self_knock(object, session_actor_id.as_str());
    let is_authorized_internal_adapter = internal_admission
        .is_some_and(|admission| admission.authorizes_realm_membership_bypass(session, object));
    let membership_subject = if ephemeral_pairwise_author || managed_actor {
        actor.to_string()
    } else {
        session_actor.to_string()
    };
    // An Applet-managed actor is an independent principal. Its immutable
    // provision and live Applet authority grant do not make it a member of the
    // portal Realm. Only its own PCR resolution rotation bypasses Realm
    // membership; ordinary writes require the managed actor's current member
    // state, even though the envelope also carries `applet_id`.
    let managed_actor_pcr_rotation =
        managed_actor && kind == arkret_wire::EventKind::IdentityResolutionUpdate.as_str();
    let applet_membership_bypass =
        applet_delegated_membership_bypass(is_applet_delegated, managed_actor);
    if !is_realm_create_bootstrap
        && !is_invite_acceptance_join
        && !is_invitee_invite_cancel
        && !is_third_party_invite_claim
        && !applet_membership_bypass
        && !managed_actor_pcr_rotation
        && !agent_delegation
        && !is_member_self_knock
        && !is_realm_bootstrap_followup
        && !is_identity_anchor_authorize
        && !is_identity_anchor_reanchor
        && !is_authorized_internal_adapter
        && !realm_has_member(state, realm_id.as_str(), &membership_subject).await
    {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "capability_denied",
            "actor is not a member of the event Realm",
        ));
    }
    require_object_field(object, "payload")?;
    validate_event_schema_and_payload(state, &kind, &schema_id, envelope, object)?;
    // The Station owns only deterministic wire admission and epoch
    // CAS. RFC 9420 group-state/frontier verification remains receiver-owned;
    // accepting a durable Commit never authorizes a member to apply it.
    let payload = object.get("payload").expect("payload required above");
    match arkret_wire::EventKind::from(kind.as_str()) {
        arkret_wire::EventKind::AgentSelectorClaim => {
            let reject = || {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    arkret_wire::ErrorCode::SCHEMA_VIOLATION,
                    "invalid controller selector claim",
                )
            };
            let claim: arkret_models_identity::AgentSelectorClaim =
                serde_json::from_value(payload.clone()).map_err(|_| reject())?;
            claim.validate().map_err(|_| reject())?;
            if claim.controller_subject_id != actor_id {
                return Err(reject());
            }
            for proof in &claim.proofs {
                let binding = claim
                    .canonical_proof_binding_bytes(proof)
                    .map_err(|_| reject())?;
                crate::jws_verify::verify_did_controlled_jws_async(
                    &binding,
                    &proof.jws,
                    &proof.verification_method,
                    claim.controller_subject_id.as_str(),
                    state,
                )
                .await
                .map_err(|_| {
                    event_validation_error(
                        StatusCode::UNAUTHORIZED,
                        arkret_wire::ErrorCode::SIGNATURE_INVALID,
                        "invalid selector controller proof",
                    )
                })?;
            }
        }
        arkret_wire::EventKind::MlsGenesis => {
            let payload = serde_json::from_value::<
                arkret_models_collaboration::events_payloads::mls::MlsGenesisPayload,
            >(payload.clone())
            .map_err(invalid_typed_mls_payload)?;
            validate_canonical_mls_group_id(payload.mls_group_id(), payload.effective_scope())?;
        }
        arkret_wire::EventKind::MlsCommit => {
            let payload =
                serde_json::from_value::<arkret_models_crypto::MlsCommitPayload>(payload.clone())
                    .map_err(invalid_typed_mls_payload)?;
            validate_canonical_mls_group_id(
                payload.mls_group_id(),
                payload.governance_binding().effective_scope(),
            )?;
        }
        arkret_wire::EventKind::MlsProposal => {
            let payload = serde_json::from_value::<
                arkret_models_collaboration::events_payloads::mls::MlsProposalPayload,
            >(payload.clone())
            .map_err(invalid_typed_mls_payload)?;
            validate_canonical_mls_group_id(
                payload.mls_group_id.as_str(),
                payload.governance_binding.effective_scope(),
            )?;
        }
        arkret_wire::EventKind::MlsWelcome => {
            let payload = serde_json::from_value::<
                arkret_models_collaboration::events_payloads::mls::MlsWelcomePayload,
            >(payload.clone())
            .map_err(invalid_typed_mls_payload)?;
            validate_canonical_mls_group_id(
                payload.mls_group_id(),
                payload.governance_binding.effective_scope(),
            )?;
        }
        _ => {}
    }
    capability_grant::validate_capability_grant_body(&kind, &actor, object)?;

    // The capability gate needs the write set, and v1 carries none on the wire:
    // the receiver projects it from `kind + payload` through the registered
    // reducer contract (`event-and-patch.md` §2.4.2). Derived here rather than
    // inside the gate so there is one evaluator, shared with
    // `enforce_registered_cell_contract` below.
    // `event-auth-state-resolution.md` section 5 - the two closed anchor units
    // carry no CBS basis field at all, so their registry plane check runs in the
    // bootstrap context. Membership of a unit is decided by the batch context
    // this validator was handed (the closed-whitelist owner is
    // `arkret_policy::realm_bootstrap::validate_realm_bootstrap_unit`, already
    // run before the batch reaches here), never guessed from the kind. The
    // authority-root claim below is resolved against that same membership, so a
    // staged genesis proof and an accepted-Seal proof can never be swapped for
    // one another.
    let bootstrap_unit_member = is_realm_bootstrap_unit_member(
        &kind,
        realm_id.as_str(),
        &actor.to_string(),
        is_realm_bootstrap_followup,
        is_identity_anchor_authorize,
        is_identity_anchor_reanchor,
        realm_bootstrap_contexts,
    );
    // `capabilities.md` section 3.2 - an Event may name the Realm authority-root
    // cell as its `authorization_ref` and thereby author under effective
    // `ak.realm.owner` instead of under a grant.
    let realm_authority_root_authorized = event_string_field(object, &["authorization_ref"])
        .as_deref()
        == Some(arkret_wire::REALM_AUTHORITY_ROOT_CELL);
    realm_authority_root::validate_realm_authority_root_authorization(
        state,
        object,
        &kind,
        realm_id.as_str(),
        &actor,
        bootstrap_unit_member,
        realm_bootstrap_contexts,
    )
    .await?;
    let ordinary_event_cells = derived_ordinary_event_cells(envelope, object, typed_digest_suite)?;
    // The MIMI facade is the sole closed service-authored message adapter. Its
    // exact current room-binding ref, provider attestation, attributed sender
    // membership and accepted MLS frontier are verified before this internal
    // admission is constructed. A service principal cannot hold a user
    // capability grant, so that closed authority tuple substitutes only for
    // the ordinary data-event capability lookup; every other validation and
    // reducer step remains shared with native Event submission.
    if !internal_admission
        .is_some_and(|admission| admission.authorizes_mimi_facade_write(session, object))
    {
        validate_ordinary_event_capability_refs(
            state,
            actor_id.as_str(),
            station_id.as_str(),
            realm_id.as_str(),
            &kind,
            object,
            &ordinary_event_cells,
            realm_authority_root_authorized,
            is_verified_applet_formal_aggregate,
        )
        .await?;
    }
    validate_control_move_seal_basis(
        object,
        is_realm_bootstrap_followup || is_identity_anchor_authorize,
    )?;
    if kind == arkret_wire::EventKind::MemberIdentityUpdate.as_str() {
        validate_member_identity_proof(state, object.get("payload").unwrap_or(&Value::Null))
            .await?;
    }
    if kind == arkret_wire::EventKind::DeviceAuthorize.as_str() {
        validate_device_authorization_binding(
            state,
            object,
            actor_id.as_str(),
            realm_bootstrap_contexts,
        )
        .await?;
    }
    validate_audit_accessed_payload(&kind, object)?;
    // Round R2/R3 (T09 + T12) — realm.policy_bundle hard ceiling,
    // policy-derived relaxed-mode mutex, and media plaintext triple binding.
    // Cross-policy bindings come from materialized Realm metadata / MLS cells, with the current
    // payload used only for same-event policy-component writes.
    if kind == arkret_wire::EventKind::RealmPolicyBundle.as_str() {
        let payload = object.get("payload").cloned().unwrap_or(Value::Null);
        let policy_bundle = policy_bundle_value_from_state_payload(&payload);
        let audit_binding_active = state
            .projections()
            .snapshot()
            .realm_has_active_audit_binding(realm_id.as_str());
        let media_plaintext_service_present =
            projected_media_plaintext_service_present(state, realm_id.as_str(), policy_bundle)
                .await;
        if let Err((code, reason)) = realm_policy_bundle_check(
            policy_bundle,
            audit_binding_active,
            media_plaintext_service_present,
        ) {
            return Err(event_validation_error(
                error_http_status(code),
                code.as_str(),
                &reason,
            ));
        }
    }
    // Round R2/R3 (T04) — Seal frontier entries MUST be sha256:<hex>.
    // We tighten the validator on the events ingest side for the
    // `ak.realm.seal.submit` payload shape used by federation push;
    // the deeper canonical-bytes path uses SDK `seal_canonical_bytes`
    // which already excludes id + notary_sig (notary.rs:217).
    if let Some(frontier) = object
        .get("payload")
        .and_then(|p| p.get("frontier"))
        .and_then(Value::as_array)
    {
        let entries: Vec<String> = frontier
            .iter()
            .filter_map(|v| v.as_str().map(ToOwned::to_owned))
            .collect();
        if let Err((code, reason)) =
            crate::routing::federation::move_seal::validate_seal_delta_entries(&entries)
        {
            return Err(event_validation_error(
                error_http_status(code),
                code.as_str(),
                &reason,
            ));
        }
    }

    finalize_validated_event_envelope(
        state,
        session,
        envelope,
        object,
        realm_bootstrap_contexts,
        internal_admission,
        EnvelopeValidationCore {
            event_id,
            actor,
            actor_id,
            actor_seq,
            realm_id,
            kind,
            schema_id,
            canonical_digest,
            digest_suite: typed_digest_suite,
            canonical_bytes,
        },
        is_identity_anchor_authorize || is_identity_anchor_reanchor,
        is_direct_conversation_founding,
        bootstrap_unit_member,
        is_applet_managed_pcr_genesis && is_verified_applet_formal_aggregate,
    )
    .await
}

struct EnvelopeValidationCore {
    event_id: EventId,
    actor: arkret_wire::ActorId,
    actor_id: arkret_wire::DidCoreId,
    actor_seq: u64,
    realm_id: RealmId,
    kind: String,
    schema_id: String,
    canonical_digest: String,
    digest_suite: arkret_canonical::DigestSuite,
    canonical_bytes: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
async fn finalize_validated_event_envelope(
    state: &AppState,
    session: &SessionRecord,
    envelope: &Value,
    object: &serde_json::Map<String, Value>,
    realm_bootstrap_contexts: &[RealmBootstrapBatchContext],
    internal_admission: Option<&InternalEventAdmission>,
    core: EnvelopeValidationCore,
    is_identity_anchor_device_event: bool,
    is_direct_conversation_founding: bool,
    bootstrap_unit_member: bool,
    privileged_bootstrap: bool,
) -> Result<ValidatedEventEnvelope, EventValidationError> {
    let prev_refs = event_ref_list(object, "prev_refs", MAX_EVENT_PREV_REFS)?
        .into_iter()
        .map(|event_id| {
            EventId::new(event_id).map_err(|_| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "param_invalid",
                    "prev_refs entries must be typed EventIds",
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    validate_created_at_causal_lower_bound(state, object, &prev_refs).await?;
    event_semantic_refs(object, MAX_EVENT_REFS)?;
    validate_strand_watch_manage_others_levels(&core.kind, object, &core.actor)?;
    let producer_signing_key = validate_event_proofs(
        object,
        state,
        session,
        core.actor_id.as_str(),
        &core.canonical_digest,
        core.digest_suite,
        &core.canonical_bytes,
        realm_bootstrap_contexts,
        internal_admission,
    )
    .await?;
    // The signature half of `join-policy.md` §4 rule 4. The reducer owns the
    // binding tuple, but resolving a gate proof's signer through a DID document
    // is admission-path work, so it runs beside the envelope proofs.
    validate_join_gate_proof_signatures(object, state).await?;
    enforce_device_generation_fence(
        state,
        session,
        object,
        core.actor_id.as_str(),
        is_identity_anchor_device_event,
        internal_admission,
    )
    .await?;
    reject_revoked_actor_device_signature(object, state, session, core.actor_id.as_str()).await?;
    let sidecar_bootstrap = internal_admission.is_some_and(|admission| {
        core.kind == arkret_wire::EventKind::SidecarCreate.as_str()
            && admission.is_sidecar_ensure(session, object)
    });
    let cbs_context = if is_direct_conversation_founding {
        arkret_schema::EventCellContractContext::DirectConversationFounding
    } else if bootstrap_unit_member || sidecar_bootstrap || privileged_bootstrap {
        arkret_schema::EventCellContractContext::OrdinaryRealmBootstrap
    } else {
        arkret_schema::EventCellContractContext::Standard
    };
    enforce_registered_cell_contract(envelope, &core.kind, cbs_context, core.digest_suite)?;
    enforce_ordered_log_cell_contract(
        state,
        envelope,
        &core.kind,
        core.realm_id.as_str(),
        object,
        realm_bootstrap_contexts,
    )
    .await?;
    // The submitting device is request context, not an Event field:
    // `event-envelope.schema.json` declares no `device_id` and closes the object.
    // A service session (applet bridge, federation source signature) authenticates
    // a service identity, which owns no device — that session carries no device id
    // and the Event is projected with no source device. A session that does name a
    // device still has to name a typed one.
    let device_id = if session.device_id.is_empty() {
        None
    } else {
        Some(DeviceId::new(session.device_id.clone()).map_err(|_| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "param_invalid",
                "device_id must be a typed DeviceId",
            )
        })?)
    };

    Ok(ValidatedEventEnvelope {
        event_id: core.event_id,
        actor: core.actor,
        actor_id: core.actor_id,
        device_id,
        actor_seq: core.actor_seq,
        realm_id: core.realm_id,
        kind: core.kind,
        schema_id: core.schema_id,
        prev_refs,
        canonical_digest: core.canonical_digest,
        digest_suite: core.digest_suite,
        canonical_bytes: core.canonical_bytes,
        producer_signing_key: Some(producer_signing_key),
    })
}

fn applet_delegated_membership_bypass(is_applet_delegated: bool, managed_actor: bool) -> bool {
    is_applet_delegated && !managed_actor
}

fn event_id_digest_mismatch_error() -> EventValidationError {
    EventValidationError {
        status: StatusCode::BAD_REQUEST,
        code: arkret_wire::ErrorCode::SchemaViolation.as_str(),
        message:
            "carried event_id does not equal the digest re-derived from the canonical Event preimage"
                .to_owned(),
        reason_code: Some(arkret_wire::ReasonCode::EVENT_ID_DIGEST_MISMATCH),
    }
}

fn validate_prelookup_event_identity(
    event_id: &str,
    canonical_digest: &str,
    canonical_bytes: &[u8],
) -> Result<(), EventValidationError> {
    soland_storage::ids::validated_event_identity_parts(event_id, canonical_digest, canonical_bytes)
        .map(|_| ())
        .map_err(|_| event_id_digest_mismatch_error())
}

fn validate_content_bound_event_id(
    envelope: &Value,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<(), EventValidationError> {
    let event =
        serde_json::from_value::<arkret_wire::Event>(envelope.clone()).map_err(|error| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                arkret_wire::ErrorCode::SchemaViolation.as_str(),
                format!("Event Envelope is not structurally valid: {error}"),
            )
        })?;
    event
        .verify_event_id_matches_content_with_digest_suite(digest_suite)
        .map_err(|_| event_id_digest_mismatch_error())
}

async fn enforce_device_generation_fence(
    state: &AppState,
    session: &SessionRecord,
    object: &serde_json::Map<String, Value>,
    actor_id: &str,
    is_identity_anchor_device_event: bool,
    internal_admission: Option<&InternalEventAdmission>,
) -> Result<(), EventValidationError> {
    let root_anchor = object
        .get("refs")
        .and_then(Value::as_array)
        .is_some_and(|refs| {
            refs.iter().any(|reference| {
                matches!(
                    reference.get("role").and_then(Value::as_str),
                    Some("did_inception" | "did_recovery_anchor")
                )
            })
        });
    if root_anchor || is_identity_anchor_device_event {
        return Ok(());
    }
    if event_uses_active_applet_registration_epoch(state, object).await? {
        return Ok(());
    }
    if session.token_hash.starts_with("proof-authenticated:") {
        return Ok(());
    }
    if let Some(verification_method) = object
        .get("proofs")
        .and_then(Value::as_array)
        .and_then(|proofs| proofs.first())
        .and_then(|proof| proof.get("verification_method"))
        .and_then(Value::as_str)
        && internal_admission.is_some_and(|admission| {
            admission
                .federated_producer_signing_key(session, object, verification_method)
                .is_some()
        })
    {
        return Ok(());
    }
    let Some(generation) =
        crate::routing::identity::device_generation::current_device_generation(state, actor_id)
            .await
            .map_err(|error| {
                event_validation_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("device generation state unavailable: {error}"),
                )
            })?
    else {
        return Ok(());
    };
    if generation.status
        == crate::routing::identity::device_generation::DeviceGenerationStatus::Conflicted
    {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "device_generation_fenced",
            "ordinary Event admission is closed while the B-model generation slot is conflicted",
        ));
    }
    if object.get("executed_by").is_some() {
        return Ok(());
    }
    let verification_method = object
        .get("proofs")
        .and_then(Value::as_array)
        .and_then(|proofs| proofs.first())
        .and_then(|proof| proof.get("verification_method"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::FORBIDDEN,
                "device_generation_fenced",
                "B-model Event proof does not identify an authorized device",
            )
        })?;
    let device_id = actor_device_id_from_verification_method(verification_method, actor_id)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::FORBIDDEN,
                "device_generation_fenced",
                "B-model Event proof is not rooted in an actor device",
            )
        })?;
    let device = state
        .identities()
        .find_device(soland_services::identity::FindDeviceQuery {
            actor_id: actor_id.to_owned(),
            device_id: device_id.clone(),
        })
        .await
        .map_err(|error| {
            event_validation_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("device generation lookup failed: {error}"),
            )
        })?
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::FORBIDDEN,
                "device_generation_fenced",
                "B-model Event signer device is not authorized",
            )
        })?;
    let authorized_generation_ref = device
        .payload
        .get("authorized_generation_ref")
        .and_then(Value::as_u64);
    if authorized_generation_ref != Some(generation.current_ref) {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "device_generation_fenced",
            "Event signer device belongs to an older B-model generation",
        ));
    }
    Ok(())
}

async fn event_uses_active_applet_registration_epoch(
    state: &AppState,
    object: &serde_json::Map<String, Value>,
) -> Result<bool, EventValidationError> {
    let Some(applet_id) = object.get("applet_id").and_then(Value::as_str) else {
        return Ok(false);
    };
    let Some(verification_method) = object
        .get("proofs")
        .and_then(Value::as_array)
        .and_then(|proofs| proofs.first())
        .and_then(|proof| proof.get("verification_method"))
        .and_then(Value::as_str)
    else {
        return Ok(false);
    };
    let signer = object
        .get("executed_by")
        .or_else(|| object.get("actor_id"))
        .cloned()
        .and_then(|value| serde_json::from_value::<arkret_wire::ActorId>(value).ok());
    let Some(signer) = signer else {
        return Ok(false);
    };
    let signer_id = signer.signing_principal_id().as_str();
    let Some(method_controller) = verification_method.split_once('#').map(|(root, _)| root) else {
        return Ok(false);
    };
    let method_controller = arkret_wire::Did::new(method_controller.to_owned())
        .and_then(|did| arkret_wire::project_did_to_core_id(&did));
    if !matches!(method_controller, Ok(ref id) if id.as_str() == signer_id) {
        return Ok(false);
    }
    let Some(scope_value) = object.get("scope_ref").cloned() else {
        return Ok(false);
    };
    let effective_scope: arkret_wire::ScopeRef =
        serde_json::from_value(scope_value).map_err(|error| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("Applet proof scope_ref is invalid: {error}"),
            )
        })?;
    let record = crate::routing::extensions::applet_bridge::record::applet_record(
        state,
        applet_id,
        &effective_scope,
    )
    .await
    .map_err(|error| {
        event_validation_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            format!("Applet proof authority lookup failed: {error}"),
        )
    })?;
    let Some(record) = record else {
        return Ok(false);
    };
    if record.revoked_at.is_some()
        || !matches!(record.status.as_str(), "installed" | "partially_installed")
    {
        return Ok(false);
    }
    let package = &record.package;
    let evidence =
        crate::routing::extensions::applet_bridge::registration_epoch_evidence_from_record(&record)
            .map_err(|error| {
                event_validation_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("stored Applet registration Event is invalid: {error}"),
                )
            })?;
    Ok(
        signer == arkret_wire::ActorId::service(package.service_id.clone())
            && package.webhook_auth.key_ref.as_str() == verification_method
            && evidence.contains_signing_key(verification_method),
    )
}

/// Run the registry cell contract for every reducer-input kind whose registry
/// row declares a contract a producer can satisfy exactly.
///
/// `models/event-and-patch.md` §2.4.2 makes the registry — not a
/// producer-selected effect — the authority for a reducer target, so admission
/// must not be a hand-maintained per-kind allow-list: a kind nobody remembered
/// to add is simply unchecked, which is how effect-less `ak.rsvp.set` Events
/// reached the projection.
///
/// The gate is therefore driven by the registry itself. It covers a kind when
/// the row declares `effect_projection` for every cell write, i.e. when the
/// complete op is a pure function of the Event and a receiver can recompute it.
/// Rows that declare a cell family without a projection are deliberately left
/// alone for now: enforcing them would reject writes current producers cannot
/// construct yet, so tightening those is a producer-side migration (every
/// client materializes registry effects) that has to land before the server can
/// fail closed on it.
/// Whether this envelope is a member of one of the two closed
/// `seal_basis`-exempt anchor units of `event-auth-state-resolution.md` §5.
///
/// The `ak.realm.create` genesis is the unit head; the whitelisted initial
/// facets and the delegated first `ak.device.authorize` are its
/// already-classified members. Nothing else may claim the exemption, so the
/// answer is read from the batch context rather than derived from the kind.
fn is_realm_bootstrap_unit_member(
    kind: &str,
    realm_id: &str,
    actor_id: &str,
    is_realm_bootstrap_followup: bool,
    is_identity_anchor_authorize: bool,
    is_identity_anchor_reanchor: bool,
    realm_bootstrap_contexts: &[RealmBootstrapBatchContext],
) -> bool {
    if is_realm_bootstrap_followup || is_identity_anchor_authorize || is_identity_anchor_reanchor {
        return true;
    }
    kind == arkret_wire::event_kind_str::REALM_CREATE
        && realm_bootstrap_contexts
            .iter()
            .any(|context| context.realm_id == realm_id && context.actor_id == actor_id)
}

/// Project the cells an ordinary Event writes, for the capability gate.
///
/// v1 has no producer `effects[]` (`event-and-patch.md` §2.2), so the set a
/// capability has to cover is the receiver's own registry projection of `kind +
/// payload`. Returns empty for anything that is not an ordinary Event; an ordinary Event
/// whose contract will not evaluate fails closed here with the same reason code
/// [`enforce_registered_cell_contract`] would raise for it later.
fn derived_ordinary_event_cells(
    envelope: &Value,
    object: &serde_json::Map<String, Value>,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<Vec<String>, EventValidationError> {
    if !object.contains_key("auth_context") {
        return Ok(Vec::new());
    }
    let event =
        serde_json::from_value::<arkret_wire::Event>(envelope.clone()).map_err(|error| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("ordinary Event is not a valid Event Envelope: {error}"),
            )
        })?;
    let projected =
        arkret_schema::project_registered_cell_writes(&event, digest_suite).map_err(|error| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                error.reason_code(),
                error.to_string(),
            )
        })?;
    Ok(projected
        .into_iter()
        .map(|write| write.cell_id.as_str().to_owned())
        .collect())
}

fn enforce_registered_cell_contract(
    envelope: &Value,
    kind: &str,
    context: arkret_schema::EventCellContractContext,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<(), EventValidationError> {
    let event_kind = arkret_wire::EventKind::from(kind);
    let Some(descriptor) = event_kind.descriptor() else {
        return Ok(());
    };
    if !descriptor.reducer_input {
        return Ok(());
    }
    let event =
        serde_json::from_value::<arkret_wire::Event>(envelope.clone()).map_err(|error| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("reducer input is not a valid Event Envelope: {error}"),
            )
        })?;
    // v1 carries no producer `effects[]`: the receiver derives every write
    // from `kind + payload` through the registered contract
    // (`event-and-patch.md` §2.4.2). The admission gate is therefore just
    // "is the registered contract evaluable for this Event" — a row whose
    // projection cannot be derived fails the Event closed, and a row that is
    // not an active reducer input projects nothing and passes.
    let contract_validation = if matches!(
        kind,
        arkret_wire::event_kind_str::INVITE_CANCEL | arkret_wire::event_kind_str::CAPABILITY_GRANT
    ) {
        // `ak.invite.cancel` is the one active contract whose validity depends
        // on authoritative invite lifecycle fields. The submit admission lane
        // freezes those fields while holding the per-Invite lock and calls
        // `project_cell_writes_with_pre_state`; evaluating the full contract
        // here with an empty placeholder would reject every valid direct
        // invite before that atomic check can run. Plane validation remains
        // mandatory at this shape-only stage. Capability Grant likewise needs
        // its parent grants' immutable authority audits; its control-move gate
        // invokes the authority-aware projector against ProjectionState.
        arkret_schema::validate_registered_cell_plane_in_context(&event, context)
    } else {
        arkret_schema::validate_registered_cell_writes_in_context(&event, context, digest_suite)
    };
    contract_validation.map_err(|error| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            error.reason_code(),
            error.to_string(),
        )
    })?;
    if kind == arkret_wire::event_kind_str::REALM_CREATE {
        // The canonical Realm-create genesis write set is likewise recomputed,
        // never compared against a submitted array. Only the *targets* are
        // asserted: the state model ops come from the registered
        // `effect_projection`, and restating them here would rebuild the
        // producer-side effect table v1 removed.
        let derived = arkret_schema::project_registered_cell_writes(&event, digest_suite).map_err(
            |error| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    error.reason_code(),
                    error.to_string(),
                )
            },
        )?;
        let expected = arkret_bootstrap::expected_realm_create_cells(&event);
        let actual: std::collections::BTreeSet<String> = derived
            .iter()
            .map(|write| write.cell_id.as_str().to_owned())
            .collect();
        if derived.len() != expected.len() || actual != expected {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "reducer_projection_failed",
                "Realm create does not derive the canonical registered genesis cells",
            ));
        }
    }
    Ok(())
}

/// Re-derive the registry-declared cell and append value for single-target
/// `ordered_log` reducer inputs.
///
/// `models/event-and-patch.md` §2.4.2 makes the registry — not a
/// producer-selected `effects[].cell` or an arbitrary `op.value` — the
/// authority for a reducer target. This is the general hook: it applies to
/// every kind whose registry row declares an ordered-log single-target
/// contract with a value projection, not only one historical carrier family
/// that first exposed the gap.
async fn enforce_ordered_log_cell_contract(
    state: &AppState,
    envelope: &Value,
    kind: &str,
    realm_id: &str,
    object: &serde_json::Map<String, Value>,
    realm_bootstrap_contexts: &[RealmBootstrapBatchContext],
) -> Result<(), EventValidationError> {
    let event_kind = arkret_wire::EventKind::from(kind);
    let Some(descriptor) = event_kind.descriptor() else {
        return Ok(());
    };
    if !descriptor.reducer_input
        || !descriptor.cell_writes.iter().any(|write| {
            write.state_model == Some(arkret_wire::EventCellStateModel::OrderedLog)
                && write.value_projection_rule.is_some()
        })
        || descriptor.value_projection_rule.is_none()
    {
        return Ok(());
    }
    // A kind that reaches here but cannot be parsed as a typed Event has
    // already failed shared envelope shape validation above; treat an
    // unparseable envelope as fail-closed rather than skipping the contract.
    let event =
        serde_json::from_value::<arkret_wire::Event>(envelope.clone()).map_err(|error| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("ordered-log reducer input is not a valid Event Envelope: {error}"),
            )
        })?;
    // device-lifecycle.md 13.0.1 pins the material digest to the Realm's active
    // digest_algorithm, so the contract cannot be checked without it.
    let suite_name =
        event_digest_suite(state, kind, realm_id, object, realm_bootstrap_contexts).await?;
    let suite = arkret_canonical::digest_suite(&suite_name)
        .map_err(|_| unsupported_digest_algorithm_error(&suite_name))?;
    // v1 has no producer `effects[]` to compare an append against: the single
    // registered evaluator either derives the append target and value from
    // `kind + payload` under this Realm's suite, or the Event fails closed.
    arkret_schema::project_registered_cell_writes(&event, suite)
        .map(|_| ())
        .map_err(|error| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                error.reason_code(),
                error.to_string(),
            )
        })
}

#[cfg(test)]
mod security_frontier_material_tests {
    use super::*;

    #[test]
    fn content_bound_event_id_rejects_post_derivation_mutation() {
        let realm_id = arkret_wire::RealmId::new(
            "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI".to_owned(),
        )
        .unwrap();
        let mut event = crate::test_event::raw_event(
            "ak.message.create",
            arkret_wire::ScopeRef::Realm { realm_id },
            crate::test_actor_id_str("did:web:alice.example"),
            0,
            arkret_wire::Hlc::new("01970e589d21-0000-a13f9c2e".to_owned()).unwrap(),
            serde_json::json!({"body": "hello"}),
        )
        .unwrap();
        validate_content_bound_event_id(
            &serde_json::to_value(&event).unwrap(),
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();

        event.actor_seq = 1;
        let error = validate_content_bound_event_id(
            &serde_json::to_value(event).unwrap(),
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap_err();

        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.code, arkret_wire::ErrorCode::SchemaViolation.as_str());
        assert_eq!(
            error.reason_code,
            Some(arkret_wire::ReasonCode::EVENT_ID_DIGEST_MISMATCH)
        );
    }

    #[test]
    fn forged_carried_id_is_rejected_by_storage_verifier_before_admission_lookup() {
        let realm_id = arkret_wire::RealmId::new(
            "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI".to_owned(),
        )
        .unwrap();
        let mut event = crate::test_event::raw_event(
            "ak.message.create",
            arkret_wire::ScopeRef::Realm { realm_id },
            crate::test_actor_id_str("did:web:alice.example"),
            0,
            arkret_wire::Hlc::new("01970e589d21-0000-a13f9c2e".to_owned()).unwrap(),
            serde_json::json!({"body": "accepted"}),
        )
        .unwrap();
        let carried_id = event.event_id.to_string();

        // Change digest-covered content while retaining an accepted Event's
        // carried id. The lookup layer must never see this candidate.
        event
            .payload
            .insert("body".to_owned(), serde_json::json!("forged"));
        let envelope = serde_json::to_value(event).unwrap();
        let canonical_bytes = event_canonical_bytes(&envelope).unwrap();
        let canonical_digest = event_digest_for_suite(&canonical_bytes, "sha256").unwrap();
        let error =
            validate_prelookup_event_identity(&carried_id, &canonical_digest, &canonical_bytes)
                .unwrap_err();

        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            error.reason_code,
            Some(arkret_wire::ReasonCode::EVENT_ID_DIGEST_MISMATCH)
        );
    }

    #[test]
    fn mls_group_id_must_match_effective_scope() {
        let realm_id = arkret_wire::RealmId::new(
            "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI".to_owned(),
        )
        .unwrap();
        let scope = arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        };
        let group_id = scope.canonical_mls_group_id().unwrap();
        validate_canonical_mls_group_id(group_id.as_str(), &scope).unwrap();
        assert!(validate_canonical_mls_group_id("wrong-group", &scope).is_err());
    }

    #[test]
    fn managed_applet_actor_never_inherits_the_delegated_membership_bypass() {
        assert!(applet_delegated_membership_bypass(true, false));
        assert!(!applet_delegated_membership_bypass(true, true));
        assert!(!applet_delegated_membership_bypass(false, true));
    }
}
