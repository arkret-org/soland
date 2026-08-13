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

fn require_verified_mls_commit_frontier_material(kind: &str) -> Result<(), EventValidationError> {
    if kind != arkret_wire::event_kind_str::MLS_COMMIT {
        return Ok(());
    }
    Err(EventValidationError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        code: arkret_wire::ErrorCode::FRONTIER_UNAVAILABLE,
        message: "verified RFC 9420 group-state material is unavailable for MLS Commit security-frontier admission".to_owned(),
        reason_code: Some(arkret_wire::ReasonCode::MLS_GOVERNANCE_BINDING_STALE),
    })
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
        false,
    ))
}

pub(in crate::routing) fn validate_private_invite_envelope<'a>(
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
    Box::pin(validate_event_envelope_with_ingress(
        state,
        session,
        envelope,
        &[],
        None,
        true,
    ))
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
    prev_refs: &[String],
) -> Result<(), EventValidationError> {
    let Some(created_at) = object
        .get("created_at")
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
    else {
        return Ok(());
    };
    for prev_ref in prev_refs {
        let Ok(Some(record)) = state.event_queries().canonical_event(prev_ref).await else {
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

async fn validate_event_envelope_with_ingress(
    state: &AppState,
    session: &SessionRecord,
    envelope: &Value,
    realm_bootstrap_contexts: &[RealmBootstrapBatchContext],
    internal_admission: Option<&InternalEventAdmission>,
    private_invite_delivery: bool,
) -> Result<ValidatedEventEnvelope, EventValidationError> {
    let object = envelope.as_object().ok_or_else(|| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_event_envelope",
            "Event Envelope must be a JSON object",
        )
    })?;
    let session_actor_id = arkret_wire::DidCoreId::new(session.actor.clone())
        .map_err(|error| {
            event_validation_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("session actor is invalid: {error}"),
            )
        })?
        .to_string();
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
            "missing_param",
            "event_id is required",
        )
    })?;
    if !is_valid_event_id(&event_id) {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "event_id must use the ak:event: typed prefix",
        ));
    }

    let kind = event_string_field(object, &["kind"]).ok_or_else(|| {
        event_validation_error(StatusCode::BAD_REQUEST, "missing_param", "kind is required")
    })?;
    // Receipt objects are not durable Event kinds. Legacy plaintext transient
    // kinds are absent from the active registry and fail the registry gate
    // below; current transient product payloads travel encrypted inside Signal.
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

    let actor_id = event_string_field(object, &["actor_id"]).ok_or_else(|| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "missing_param",
            "actor_id is required",
        )
    })?;
    if arkret_wire::DidCoreId::new(actor_id.clone()).is_err() {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "actor_id must be a Core DidCoreId",
        ));
    }
    let principal_server_id = event_string_field(object, &["principal_server_id"])
        .and_then(|value| arkret_wire::DidCoreId::new(value).ok())
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_param",
                "principal_server_id must be a Core DidCoreId",
            )
        })?;
    let actor_seq = object
        .get("actor_seq")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "missing_param",
                "actor_seq is required",
            )
        })?;
    validate_event_time_fields(state, object)?;
    let realm_id = event_realm_id(object)?;

    // Identity verification is deliberately the last purely local gate before
    // any admission lookup. The suite comes from the trusted Realm projection
    // (or the signed Realm-create payload), then the shared storage verifier
    // recomputes the exact digest preimage and binds the complete EventId.
    let canonical_bytes = event_canonical_bytes(envelope)?;
    let digest_suite =
        event_digest_suite(state, &kind, &realm_id, object, realm_bootstrap_contexts)?;
    let canonical_digest = event_digest_for_suite(&canonical_bytes, &digest_suite)?;
    validate_prelookup_event_identity(&event_id, &canonical_digest, &canonical_bytes)?;
    let typed_digest_suite = arkret_canonical::digest_suite(&digest_suite)
        .map_err(|_| unsupported_digest_algorithm_error(&digest_suite))?;
    validate_content_bound_event_id(envelope, typed_digest_suite)?;

    // A closed internal adapter (policy-server self-management, moderation
    // report, MIMI ingress, ...) authors the Event on behalf of the
    // authenticated caller under the service's own session, so its
    // `actor_id` is the caller while `session.actor` is the service.
    // `InternalEventAdmission::matches` binds that pairing exactly — session
    // actor, session device, Event actor, Realm, kind and the per-binding
    // payload — so it has to be resolved before the generic actor/session
    // equality gate below, not after it.
    let is_authorized_internal_adapter =
        internal_admission.is_some_and(|admission| admission.matches(session, object));
    let ephemeral_pairwise_author = if actor_id != session_actor_id
        && !is_authorized_internal_adapter
    {
        let context =
            super::minimal_metadata_author::minimal_metadata_author_context(object, state).await;
        super::minimal_metadata_author::is_ephemeral_pairwise_author(&actor_id, context.as_ref())
    } else {
        false
    };
    let managed_agent_delegation = if actor_id != session_actor_id
        && !is_authorized_internal_adapter
        && !ephemeral_pairwise_author
    {
        match crate::routing::identity::managed_agent_pcr::validate_delegated_agent_envelope(
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
                    "delegated managed Agent Event validation failed"
                );
                false
            }
        }
    } else {
        false
    };
    if actor_id != session_actor_id
        && !managed_agent_delegation
        && !is_authorized_internal_adapter
        && !ephemeral_pairwise_author
    {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "actor_session_mismatch",
            "event actor_id must match the bearer session actor",
        ));
    }

    // REDU-7 / AKP-0008 / AKP-0009 (R3 spec-sync 2026-05-27,
    // arkret-spec b47ff6ec) — Envelope `actor_kind` is reducer-managed:
    // reject any client-supplied value with the spec-canonical
    // `actor_kind_reducer_managed` reason code. The reducer derives the
    // canonical `EnvelopeActorKind` (Native/Ghost/Service/Agent) from
    // the Actor Profile after the bearer-session derivation lands.
    // TODO(P2-impl): once the deep reducer pipeline runs here, stamp the
    // canonical `EnvelopeActorKind` onto the persisted projection envelope.
    if object.get("actor_kind").is_some() {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            arkret_wire::ReasonCode::ACTOR_KIND_REDUCER_MANAGED,
            "envelope.actor_kind is reducer-managed; clients MUST NOT supply it",
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
                "invalid_param",
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
            .and_then(|did| arkret_wire::DidFullId::new(did.to_owned()).ok())
            .and_then(|did| arkret_wire::project_full_id_to_core_id(&did).ok());
        if vm_actor.as_ref() != Some(&executed_by) {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "executed_by_mismatch",
                "envelope.executed_by must match the DID derived from proof.verification_method",
            ));
        }
    }

    let is_applet_delegated = object.get("applet_id").is_some();
    // The closed applet provisioning adapter has already verified the installed
    // registration, ghost namespace and provision request before constructing
    // this exact signed Event. Its first formal profile Event is authorized by
    // the accountability-grant Event persisted immediately before it, rather
    // than by an `ak:grant:*` capability object in the runtime grant index.
    if !is_authorized_internal_adapter {
        validate_applet_delegated_authorization_chain(state, object, &kind, &actor_id, &realm_id)
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
        .realm_is_in_terminal_state(&realm_id);
    if let Some((code, reason)) = terminal_realm_check(realm_terminal, &kind) {
        return Err(event_validation_error(
            error_http_status(code),
            code.as_str(),
            reason,
        ));
    }
    let realm_frozen = state
        .projections()
        .snapshot()
        .realm_is_frozen_at(&realm_id, chrono::Utc::now());
    if let Some(reason) = frozen_realm_check(realm_frozen, &kind) {
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
    let realm_exists = realm_exists_in_index(state, &realm_id);
    // A managed-Agent PCR create is initially published through the batch
    // surface, then may be replayed through the single-submission surface to
    // recover its stored Control Proposal Ack. Let an already accepted Event id
    // reach the submitter's canonical-byte duplicate check; only a different
    // create for the existing Realm is a `realm_already_exists` conflict here.
    let historical_realm_create =
        if kind == arkret_wire::EventKind::RealmCreate.as_str() && realm_exists {
            state
                .event_queries()
                .canonical_event(&event_id)
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
    let is_realm_create_bootstrap = kind == arkret_wire::EventKind::RealmCreate.as_str()
        && realm_create_actor_is_creator(object, &actor_id)
        && (actor_id == session_actor_id || managed_agent_delegation)
        && (!realm_exists || historical_realm_create);
    let is_invite_acceptance_join =
        member_join_accepts_pending_invite(state, object, &session_actor_id, &realm_id).await;
    let is_invitee_invite_cancel =
        invitee_cancels_pending_invite(state, object, &session_actor_id, &realm_id).await;
    let is_third_party_invite_claim = invite_claim_actor_claims_pending_third_party_invite(
        state,
        object,
        &session_actor_id,
        &realm_id,
    )
    .await;
    // `/_arkret/peer/invites` verifies the original signed Event before
    // projecting a holder-private inbox record. This explicit ingress context
    // bypasses only the local shared-Realm membership lookup: it never commits
    // the Event or advances a reducer/frontier on the recipient service.
    let is_private_invite_delivery = private_invite_delivery
        && kind == arkret_wire::EventKind::InviteCreate.as_str()
        && invite_create_actor_is_inviter(object, &session_actor_id)
        && !realm_exists;
    let is_direct_conversation_founding = realm_bootstrap_contexts
        .iter()
        .any(|context| context.direct_conversation_founding);
    let is_realm_bootstrap_followup = is_direct_conversation_founding
        || (is_realm_bootstrap_followup_kind(&kind)
            && realm_bootstrap_contexts
                .iter()
                .any(|context| context.realm_id == realm_id && context.actor_id == actor_id));
    let is_identity_anchor_authorize = kind == arkret_wire::EventKind::DeviceAuthorize.as_str()
        && realm_bootstrap_contexts.iter().any(|context| {
            context.realm_id == realm_id
                && context.actor_id == actor_id
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
            context.realm_id == realm_id
                && context.actor_id == actor_id
                && context.identity_anchor_event_id.as_deref() == Some(event_id.as_str())
        });
    // join-policy.md §7.1 — a not-yet-member applicant MUST be able to submit
    // their own `ak.member.state{membership=knock}` (and the profile-private
    // application sub-payload it carries). Gate / review enforcement happens at
    // the later `join` transition, not on the knock itself.
    let is_member_self_knock = member_self_knock(object, &session_actor_id);
    let is_authorized_internal_adapter = internal_admission
        .is_some_and(|admission| admission.authorizes_realm_membership_bypass(session, object));
    let membership_subject = if ephemeral_pairwise_author {
        actor_id.as_str()
    } else {
        session_actor_id.as_str()
    };
    if !is_realm_create_bootstrap
        && !is_invite_acceptance_join
        && !is_invitee_invite_cancel
        && !is_third_party_invite_claim
        && !is_private_invite_delivery
        && !is_applet_delegated
        && !managed_agent_delegation
        && !is_member_self_knock
        && !is_realm_bootstrap_followup
        && !is_identity_anchor_authorize
        && !is_identity_anchor_reanchor
        && !is_authorized_internal_adapter
        && !realm_has_member(state, &realm_id, membership_subject).await
    {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "capability_denied",
            "actor is not a member of the event Realm",
        ));
    }
    require_object_field(object, "payload")?;
    let is_self_principal_pcr_bootstrap_create = kind
        == arkret_wire::EventKind::RealmCreate.as_str()
        && realm_bootstrap_contexts.iter().any(|context| {
            context.self_principal_pcr_bootstrap
                && context.realm_id == realm_id
                && context.actor_id == actor_id
                && context.identity_anchor_event_id.as_deref() == Some(event_id.as_str())
        });
    validate_event_schema_and_payload(
        state,
        &kind,
        &schema_id,
        envelope,
        object,
        is_self_principal_pcr_bootstrap_create,
    )?;
    // Commit admission requires a receiver-owned RFC 9420 public-group view:
    // accepted GroupInfo + ratchet-tree bytes establish the actual leaf
    // indexes, and the candidate Commit advances that verified tree before the
    // SDK projector compares security_frontier_digest. The current registered
    // carrier exposes only genesis digests, so deriving leaves from claimed
    // KeyPackage iteration order would invent tree positions. Stay fail-closed
    // until the standard digest-verified group-state material operation is
    // available; do not accept the producer-supplied digest on shape alone.
    require_verified_mls_commit_frontier_material(&kind)?;
    capability_grant::validate_capability_grant_body(&kind, &actor_id, object)?;

    // The capability gate needs the write set, and v1 carries none on the wire:
    // the receiver projects it from `kind + payload` through the registered
    // reducer contract (`event-and-patch.md` §2.4.2). Derived here rather than
    // inside the gate so there is one evaluator, shared with
    // `enforce_registered_cell_contract` below.
    // `event-auth-state-resolution.md` section 5 - the two closed anchor units
    // carry no CBA basis field at all, so their registry plane check runs in the
    // bootstrap context. Membership of a unit is decided by the batch context
    // this validator was handed (the closed-whitelist owner is
    // `arkret_policy::realm_bootstrap::validate_realm_bootstrap_unit`, already
    // run before the batch reaches here), never guessed from the kind. The
    // authority-root claim below is resolved against that same membership, so a
    // staged genesis proof and an accepted-Seal proof can never be swapped for
    // one another.
    let bootstrap_unit_member = is_realm_bootstrap_unit_member(
        &kind,
        &realm_id,
        &actor_id,
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
        &realm_id,
        &actor_id,
        bootstrap_unit_member,
        realm_bootstrap_contexts,
    )?;
    let data_event_cells = derived_data_event_cells(envelope, object)?;
    validate_data_event_capability_refs(
        state,
        &actor_id,
        principal_server_id.as_str(),
        &realm_id,
        &kind,
        object,
        &data_event_cells,
        realm_authority_root_authorized,
    )?;
    validate_control_move_seal_basis(
        object,
        is_realm_bootstrap_followup || is_identity_anchor_authorize,
    )?;
    if kind == arkret_wire::EventKind::MemberIdentityUpdate.as_str() {
        validate_member_identity_proof(state, object.get("payload").unwrap_or(&Value::Null))
            .await?;
    }
    if kind == arkret_wire::EventKind::DeviceAuthorize.as_str() {
        validate_device_authorization_binding(state, object, &actor_id, realm_bootstrap_contexts)
            .await?;
    }
    if kind == arkret_wire::EventKind::AccountStatus.as_str() {
        validate_account_status_service_binding(state, object).await?;
    }
    validate_audit_accessed_payload(&kind, object)?;
    // Round R2/R3 (T09 + T12) — realm.policy_bundle hard ceiling,
    // e2ee_relaxed mutex, and media plaintext triple binding. Active
    // profile set comes from the submitted policy-components payload;
    // cross-policy bindings come from the materialized Realm metadata /
    // MLS cells, with the current payload used only for same-event writes.
    if kind == arkret_wire::EventKind::RealmPolicyBundle.as_str() {
        let payload = object.get("payload").cloned().unwrap_or(Value::Null);
        let policy_bundle = policy_bundle_value_from_state_payload(&payload);
        // Best-effort: collect active profiles from the payload's own
        // `profiles[]` field plus any payload-asserted "active_profiles".
        let mut active_profiles: Vec<String> = policy_bundle
            .get("profiles")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        if let Some(extra) = policy_bundle
            .get("active_profiles")
            .and_then(Value::as_array)
        {
            for v in extra {
                if let Some(s) = v.as_str() {
                    active_profiles.push(s.to_owned());
                }
            }
        }
        let media_plaintext_service_present =
            projected_media_plaintext_service_present(state, &realm_id, policy_bundle).await;
        if let Err((code, reason)) = realm_policy_bundle_check(
            policy_bundle,
            &active_profiles,
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

    let prev_refs = event_ref_list(object, "prev_refs", MAX_EVENT_PREV_REFS)?;
    validate_created_at_causal_lower_bound(state, object, &prev_refs).await?;
    event_semantic_refs(object, MAX_EVENT_REFS)?;
    validate_strand_watch_manage_others_levels(&kind, object, &actor_id)?;
    let producer_signing_key = validate_event_proofs(
        object,
        state,
        session,
        &actor_id,
        &canonical_digest,
        typed_digest_suite,
        &canonical_bytes,
        realm_bootstrap_contexts,
        internal_admission,
    )
    .await?;
    enforce_device_generation_fence(
        state,
        session,
        object,
        &actor_id,
        is_identity_anchor_authorize,
        internal_admission,
    )
    .await?;
    reject_revoked_actor_device_signature(object, state, session, &actor_id).await?;
    let sidecar_bootstrap = internal_admission.is_some_and(|admission| {
        kind == arkret_wire::EventKind::SidecarCreate.as_str()
            && admission.is_sidecar_ensure(session, object)
    });
    let cba_context = if is_direct_conversation_founding {
        arkret_schema::EventCellContractContext::DirectConversationFounding
    } else if bootstrap_unit_member || sidecar_bootstrap {
        arkret_schema::EventCellContractContext::OrdinaryRealmBootstrap
    } else {
        arkret_schema::EventCellContractContext::Standard
    };
    enforce_registered_cell_contract(envelope, &kind, cba_context)?;
    enforce_ordered_log_cell_contract(
        state,
        envelope,
        &kind,
        &realm_id,
        object,
        realm_bootstrap_contexts,
    )?;
    let device_id =
        event_string_field(object, &["device_id"]).unwrap_or_else(|| session.device_id.clone());

    Ok(ValidatedEventEnvelope {
        event_id,
        actor_id,
        device_id,
        actor_seq,
        realm_id,
        kind,
        schema_id,
        prev_refs,
        canonical_digest,
        canonical_bytes,
        producer_signing_key: Some(producer_signing_key),
    })
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
    is_identity_anchor_authorize: bool,
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
    if root_anchor || is_identity_anchor_authorize {
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
        .and_then(Value::as_str);
    if authorized_generation_ref != Some(generation.current_ref.as_str()) {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "device_generation_fenced",
            "Event signer device belongs to an older B-model generation",
        ));
    }
    Ok(())
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

/// Project the cells a DataEvent writes, for the capability gate.
///
/// v1 has no producer `effects[]` (`event-and-patch.md` §2.2), so the set a
/// capability has to cover is the receiver's own registry projection of `kind +
/// payload`. Returns empty for anything that is not a DataEvent; a DataEvent
/// whose contract will not evaluate fails closed here with the same reason code
/// [`enforce_registered_cell_contract`] would raise for it later.
fn derived_data_event_cells(
    envelope: &Value,
    object: &serde_json::Map<String, Value>,
) -> Result<Vec<String>, EventValidationError> {
    if !object.contains_key("seal_ref") && !object.contains_key("auth_context") {
        return Ok(Vec::new());
    }
    let event =
        serde_json::from_value::<arkret_wire::Event>(envelope.clone()).map_err(|error| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("DataEvent is not a valid Event Envelope: {error}"),
            )
        })?;
    let projected = arkret_schema::project_registered_cell_writes(
        &event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .map_err(|error| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            error.reason_code(),
            error.to_string(),
        )
    })?;
    Ok(projected
        .into_iter()
        .map(|write| write.cell.as_str().to_owned())
        .collect())
}

fn enforce_registered_cell_contract(
    envelope: &Value,
    kind: &str,
    context: arkret_schema::EventCellContractContext,
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
    let contract_validation = if kind == arkret_wire::event_kind_str::INVITE_CANCEL {
        // `ak.invite.cancel` is the one active contract whose validity depends
        // on authoritative invite lifecycle fields. The submit admission lane
        // freezes those fields while holding the per-Invite lock and calls
        // `project_cell_writes_with_pre_state`; evaluating the full contract
        // here with an empty placeholder would reject every valid direct
        // invite before that atomic check can run. Plane validation remains
        // mandatory at this shape-only stage.
        arkret_schema::validate_registered_cell_plane_in_context(&event, context)
    } else {
        arkret_schema::validate_registered_cell_writes_in_context(&event, context)
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
        // asserted: the lattice ops come from the registered
        // `effect_projection`, and restating them here would rebuild the
        // producer-side effect table v1 removed.
        let derived = arkret_schema::project_registered_cell_writes(
            &event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .map_err(|error| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                error.reason_code(),
                error.to_string(),
            )
        })?;
        let expected = arkret_bootstrap::expected_realm_create_cells(&event);
        let actual: std::collections::BTreeSet<String> = derived
            .iter()
            .map(|write| write.cell.as_str().to_owned())
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
/// contract with a value projection, not just the realm-key delivery family
/// that first exposed the gap.
fn enforce_ordered_log_cell_contract(
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
        || descriptor.lattice != Some("ordered_log")
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
    let suite_name = event_digest_suite(state, kind, realm_id, object, realm_bootstrap_contexts)?;
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
    fn mls_commit_fails_closed_without_verified_group_state_material() {
        let error = require_verified_mls_commit_frontier_material(
            arkret_wire::EventKind::MlsCommit.as_str(),
        )
        .unwrap_err();
        assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error.code, arkret_wire::ErrorCode::FRONTIER_UNAVAILABLE);
        assert_eq!(
            error.reason_code,
            Some(arkret_wire::ReasonCode::MLS_GOVERNANCE_BINDING_STALE)
        );
    }

    #[test]
    fn non_commit_events_do_not_use_the_commit_material_gate() {
        require_verified_mls_commit_frontier_material(arkret_wire::EventKind::MlsGenesis.as_str())
            .unwrap();
    }
}
