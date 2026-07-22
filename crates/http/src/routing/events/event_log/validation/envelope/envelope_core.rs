use super::*;
use crate::routing::events::event_log::submit::InternalEventAdmission;

#[cfg(test)]
pub(crate) async fn validate_event_envelope(
    state: &AppState,
    session: &SessionRecord,
    envelope: &Value,
) -> Result<ValidatedEventEnvelope, EventValidationError> {
    validate_event_envelope_with_context(state, session, envelope, &[], None).await
}

pub(crate) async fn validate_event_envelope_with_context(
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
    validate_event_critical_features(state, object)?;

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
    // Round R2/R3 (T02/T23) — reject ephemeral kinds & receipt-object-only
    // kinds at the submit entrypoint. Aggressive mode: no compat path —
    // pre-Round-R2/R3 senders MUST switch to ak.schema.ephemeral_envelope.v1
    // (broadcast forms) or ak.schema.device_message.v1 (ak.key.verification.*).
    if let Some((code, reason)) = events_submit_pre_admit_check(&kind) {
        return Err(event_validation_error(
            error_http_status(code),
            code.as_str(),
            reason,
        ));
    }
    if !artifacts::active_local_operation_event_kinds().contains(&kind)
        && kind != kinds::CONFLICT_REPAIR
    {
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
    if validate_did(&actor_id).is_err() {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "actor_id must be a DID",
        ));
    }
    let managed_agent_delegation = if actor_id != session.actor {
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
    if actor_id != session.actor && !managed_agent_delegation {
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
            arkret_core::ReasonCode::ACTOR_KIND_REDUCER_MANAGED,
            "envelope.actor_kind is reducer-managed; clients MUST NOT supply it",
        ));
    }
    if object.get("effective_scope").is_some() {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            arkret_core::ReasonCode::EFFECTIVE_SCOPE_REDUCER_MANAGED,
            "envelope.effective_scope is reducer-managed; clients MUST NOT supply it",
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
        if validate_did(&executed_by).is_err() {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_param",
                "executed_by must be a DID",
            ));
        }
        let proofs = object
            .get("proofs")
            .and_then(Value::as_array)
            .and_then(|arr| arr.first())
            .and_then(Value::as_object);
        let vm = proofs.and_then(|proof| event_string_field(proof, &["verification_method"]));
        let vm_did = vm
            .as_deref()
            .map(|raw| raw.split_once('#').map_or(raw, |(did, _)| did));
        if vm_did != Some(executed_by.as_str()) {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "executed_by_mismatch",
                "envelope.executed_by must match the DID derived from proof.verification_method",
            ));
        }
    }

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
    let is_applet_delegated = object.get("applet_id").is_some();
    let is_authorized_internal_adapter =
        internal_admission.is_some_and(|admission| admission.matches(session, object));
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
        .projection_application()
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
        .projection_application()
        .snapshot()
        .realm_is_frozen_at(&realm_id, chrono::Utc::now());
    if let Some(reason) = frozen_realm_check(realm_frozen, &kind) {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            arkret_core::ErrorCode::REALM_FROZEN,
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
    if kind == arkret_core::events::EventKind::REALM_CREATE && realm_exists {
        return Err(event_validation_error(
            StatusCode::CONFLICT,
            "realm_already_exists",
            "realm already exists",
        ));
    }
    let is_realm_create_bootstrap = kind == "ak.realm.create"
        && realm_create_actor_is_creator(object, &actor_id)
        && (actor_id == session.actor || managed_agent_delegation)
        && !realm_exists;
    let is_invite_acceptance_join =
        member_join_accepts_pending_invite(state, object, &session.actor, &realm_id).await;
    let is_invitee_invite_cancel =
        invitee_cancels_pending_invite(state, object, &session.actor, &realm_id).await;
    let is_third_party_invite_claim = invite_claim_actor_claims_pending_third_party_invite(
        state,
        object,
        &session.actor,
        &realm_id,
    )
    .await;
    // A private cross-PS invite delivery (`POST /_arkret/peer/invites`) submits
    // the inviter-signed `ak.invite.create` on the *recipient* PS so the local
    // subject can list + accept it. That realm lives on the inviter's PS, so the
    // recipient PS has no member record for it — yet it MUST still record the
    // pending invite for its subject. Admit `ak.invite.create` from its own
    // inviter into a realm this PS does not host (spec invite-addressing.md §5).
    let is_foreign_invite_delivery = kind == "ak.invite.create"
        && invite_create_actor_is_inviter(object, &session.actor)
        && !realm_exists;
    let is_realm_bootstrap_followup = is_realm_bootstrap_followup_kind(&kind)
        && realm_bootstrap_contexts
            .iter()
            .any(|context| context.realm_id == realm_id && context.actor_id == actor_id);
    let is_realm_founding_grant = kind == arkret_core::events::EventKind::CAPABILITY_GRANT
        && realm_bootstrap_contexts.iter().any(|context| {
            context.ordinary_realm_bootstrap
                && context.realm_id == realm_id
                && context.actor_id == actor_id
        });
    let is_identity_anchor_authorize = kind == arkret_core::events::EventKind::DEVICE_AUTHORIZE
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
    // join-policy.md §7.1 — a not-yet-member applicant MUST be able to submit
    // their own `ak.member.state{membership=knock}` (and the profile-private
    // application sub-payload it carries). Gate / review enforcement happens at
    // the later `join` transition, not on the knock itself.
    let is_member_self_knock = member_self_knock(object, &session.actor);
    let is_authorized_internal_adapter = internal_admission
        .is_some_and(|admission| admission.authorizes_realm_membership_bypass(session, object));
    if !is_realm_create_bootstrap
        && !is_invite_acceptance_join
        && !is_invitee_invite_cancel
        && !is_third_party_invite_claim
        && !is_foreign_invite_delivery
        && !is_applet_delegated
        && !managed_agent_delegation
        && !is_member_self_knock
        && !is_realm_bootstrap_followup
        && !is_realm_founding_grant
        && !is_identity_anchor_authorize
        && !is_authorized_internal_adapter
        && !realm_has_member(state, &realm_id, &session.actor).await
    {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "capability_denied",
            "actor is not a member of the event Realm",
        ));
    }
    require_object_field(object, "payload")?;
    let is_self_principal_pcr_bootstrap_create = kind
        == arkret_core::events::EventKind::REALM_CREATE
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
    capability_grant_proofs::validate_capability_grant_proofs(
        state,
        session,
        &kind,
        &actor_id,
        object,
        internal_admission,
    )
    .await?;
    validate_data_event_capability_refs(state, &actor_id, &realm_id, &kind, object)?;
    validate_cba_effect_planes(object)?;
    validate_control_move_seal_basis(
        object,
        is_realm_bootstrap_followup || is_realm_founding_grant || is_identity_anchor_authorize,
    )?;
    if kind == arkret_core::events::EventKind::MEMBER_IDENTITY_UPDATE {
        validate_member_identity_proof(state, object.get("payload").unwrap_or(&Value::Null))
            .await?;
    }
    if kind == "ak.device.authorize" {
        validate_device_enrollment_authority_binding(state, object, &actor_id).await?;
    }
    validate_audit_accessed_payload(&kind, object)?;
    // Round R2/R3 (T08) — cross_domain replay defence MUST run BEFORE the
    // signature check (verified below in `validate_event_proofs`). Aggressive
    // mode: payload missing the new required fields surfaces as
    // schema_violation here; payload with mismatched trust_domain surfaces as
    // the registered `cross_domain_replay_rejected` (409) code.
    if kind == "ak.cross_signing.reset" {
        let payload = object.get("payload").cloned().unwrap_or(Value::Null);
        if let Err((code, reason)) =
            cross_signing_reset_replay_check(&payload, &event_id, &state.config().trust_domain)
        {
            return Err(event_validation_error(
                error_http_status(code),
                code.as_str(),
                &reason,
            ));
        }
    }
    // Round R2/R3 (T09 + T12) — realm.policy_components hard ceiling,
    // e2ee_relaxed mutex, and media plaintext triple binding. Active
    // profile set comes from the submitted policy-components payload;
    // cross-policy bindings come from the materialized Realm metadata /
    // MLS cells, with the current payload used only for same-event writes.
    if kind == "ak.realm.policy_components" {
        let payload = object.get("payload").cloned().unwrap_or(Value::Null);
        let policy_components = policy_components_value_from_state_payload(&payload);
        // Best-effort: collect active profiles from the payload's own
        // `profiles[]` field plus any payload-asserted "active_profiles".
        let mut active_profiles: Vec<String> = policy_components
            .get("profiles")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        if let Some(extra) = policy_components
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
            projected_media_plaintext_service_present(state, &realm_id, policy_components).await;
        let mls_governance_binding_covers_policy_root =
            projected_mls_governance_binding_covers_policy_root(
                state,
                &realm_id,
                policy_components,
            );
        let binding_discussion_metadata_digest =
            projected_mls_governance_binding_metadata_digest(state, &realm_id);
        if let Err((code, reason)) = realm_policy_components_check(
            policy_components,
            &active_profiles,
            media_plaintext_service_present,
            mls_governance_binding_covers_policy_root,
            binding_discussion_metadata_digest.as_deref(),
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
    let authorized_refs = event_semantic_refs(object, MAX_EVENT_REFS)?;
    let canonical_bytes = event_canonical_bytes(envelope)?;
    let digest_suite = event_digest_suite(state, &kind, &realm_id, object)?;
    let canonical_digest = event_digest_for_suite(&canonical_bytes, &digest_suite)?;
    validate_strand_watch_audit_pair(
        state,
        &kind,
        object,
        &event_id,
        &actor_id,
        &canonical_digest,
    )
    .await?;
    validate_event_proofs(
        object,
        state,
        session,
        &actor_id,
        &canonical_digest,
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
        authorized_refs,
        canonical_digest,
        canonical_bytes,
    })
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
                .signer_key_evidence(session, object, verification_method)
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
        .identity_application()
        .find_device(soland_application::identity::FindDeviceQuery {
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
