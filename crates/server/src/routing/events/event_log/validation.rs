use super::*;

pub(crate) fn canonical_json_hash(value: &Value) -> String {
    canonical::canonical_sha256(value).unwrap_or_else(|_| {
        let bytes = serde_json::to_vec(value).unwrap_or_default();
        cokret_sdk::canonical::sha256_digest(&bytes)
    })
}

pub(crate) fn preflight_mls_projection_reject(
    proj: &crate::reducer::ProjectionState,
    operation: &Operation,
) -> Option<String> {
    let kind = kinds::canonical_kind_string(operation);
    match kind.as_str() {
        kinds::CK_MLS_KEYPACKAGE
        | kinds::CK_MLS_WELCOME
        | kinds::CK_MLS_GENESIS
        | kinds::CK_MLS_COMMIT => {
            let mut snapshot = proj.clone();
            let effect = match kind.as_str() {
                kinds::CK_MLS_KEYPACKAGE => {
                    match operation.payload.get("action").and_then(Value::as_str) {
                        Some("publish") => {
                            crate::reducer::mls::apply_keypackage_publish(&mut snapshot, operation)
                        }
                        Some("claim") => {
                            crate::reducer::mls::apply_keypackage_claim(&mut snapshot, operation)
                        }
                        Some(other) => crate::reducer::ProjectionEffect::Rejected {
                            reason: format!("mls_keypackage_action_unknown:{other}"),
                        },
                        None => crate::reducer::ProjectionEffect::Rejected {
                            reason: "mls_keypackage_action_missing".to_owned(),
                        },
                    }
                }
                kinds::CK_MLS_WELCOME => {
                    crate::reducer::mls::apply_welcome_enqueue(&mut snapshot, operation)
                }
                kinds::CK_MLS_GENESIS => {
                    crate::reducer::mls::apply_group_genesis(&mut snapshot, operation)
                }
                kinds::CK_MLS_COMMIT => {
                    crate::reducer::mls::apply_commit_epoch(&mut snapshot, operation)
                }
                _ => crate::reducer::ProjectionEffect::Ignored,
            };
            match effect {
                crate::reducer::ProjectionEffect::Rejected { reason } => Some(reason),
                _ => None,
            }
        }
        _ => None,
    }
}

/// P2 — surface the moderation reducer's §5.5.2 fail-closed rejections at
/// ingest, mirroring [`preflight_mls_projection_reject`]. Runs the moderation
/// reducer against a clone of the live projection so the
/// separation-of-duties / overturn↔lift / modify↔new-decision constraints
/// reject the event with the canonical reason_code BEFORE it is committed.
///
/// The clone sees the same already-applied cells as the real apply will —
/// within an ordered submit batch the paired `ck.moderation.decision.lift` /
/// new `ck.moderation.decision` were applied to the live projection by their
/// own earlier `submit_event_value` calls, so the cell already reflects them.
pub(crate) fn preflight_moderation_projection_reject(
    proj: &crate::reducer::ProjectionState,
    operation: &Operation,
    hlc: &crate::hlc::ServerHlc,
) -> Option<String> {
    let kind = kinds::canonical_kind_string(operation);
    let is_moderation = matches!(
        kind.as_str(),
        kinds::CK_MODERATION_DECISION
            | kinds::CK_MODERATION_DECISION_LIFT
            | kinds::CK_MODERATION_APPEAL_SUBMIT
            | kinds::CK_MODERATION_APPEAL_REVIEW
            | kinds::CK_MODERATION_APPEAL_DECISION
            | kinds::CK_MODERATION_APPEAL_CLOSE
    );
    if !is_moderation {
        return None;
    }
    let mut snapshot = proj.clone();
    match snapshot.apply(operation, hlc) {
        crate::reducer::ProjectionEffect::Rejected { reason } => Some(reason),
        _ => None,
    }
}

fn event_realm_id(object: &serde_json::Map<String, Value>) -> Result<String, EventValidationError> {
    if let Some(realm_id) = event_string_field(object, &["realm_id"]) {
        if RealmId::new(realm_id.clone()).is_err() {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_param",
                "realm_id must use the ck:realm: typed prefix",
            ));
        }
        return Ok(realm_id.clone());
    }

    Err(event_validation_error(
        StatusCode::BAD_REQUEST,
        "missing_param",
        "realm_id is required",
    ))
}

pub(crate) async fn validate_event_envelope(
    state: &AppState,
    session: &SessionRecord,
    envelope: &Value,
) -> Result<ValidatedEventEnvelope, EventValidationError> {
    let object = envelope.as_object().ok_or_else(|| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_event_envelope",
            "Event Envelope must be a JSON object",
        )
    })?;
    validate_event_critical_features(object)?;

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
            "event_id must use the ck:event: typed prefix",
        ));
    }

    let kind = event_string_field(object, &["kind"]).ok_or_else(|| {
        event_validation_error(StatusCode::BAD_REQUEST, "missing_param", "kind is required")
    })?;
    // Round R2/R3 (T02/T23) — reject ephemeral kinds & receipt-object-only
    // kinds at the submit entrypoint. Aggressive mode: no compat path —
    // pre-Round-R2/R3 senders MUST switch to ck.schema.ephemeral_envelope.v1
    // (broadcast forms) or ck.schema.device_message.v1 (ck.key.verification.*).
    if let Some((code, reason)) = events_submit_pre_admit_check(&kind) {
        return Err(event_validation_error(
            error_http_status(code),
            code.as_str(),
            reason,
        ));
    }
    if !artifacts::active_local_operation_event_kinds().contains(&kind)
        && kind != kinds::CK_CONFLICT_REPAIR
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
    if actor_id != session.actor {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "actor_session_mismatch",
            "event actor_id must match the bearer session actor",
        ));
    }

    // REDU-7 / CKP-0008 / CKP-0009 (R3 spec-sync 2026-05-27,
    // cokret-spec b47ff6ec) — Envelope `actor_kind` is reducer-managed:
    // reject any client-supplied value with the spec-canonical
    // `actor_kind_reducer_managed` reason code. The reducer derives the
    // canonical `EnvelopeActorKind` (Native/Ghost/Service/Agent) from
    // the Actor Profile after the bearer-session derivation lands.
    // TODO(P2-impl): once the deep reducer pipeline runs here, stamp the
    // canonical `EnvelopeActorKind` onto the persisted projection envelope.
    if object.get("actor_kind").is_some() {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            crate::error::reasons::ACTOR_KIND_REDUCER_MANAGED,
            "envelope.actor_kind is reducer-managed; clients MUST NOT supply it",
        ));
    }

    // CKP-0008 / CKP-0009 — when `executed_by` is present the reducer MUST
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
    if actor_seq == 0 {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "actor_seq must be greater than zero",
        ));
    }
    validate_event_time_fields(state, object)?;

    let realm_id = event_realm_id(object)?;
    // Round R2/R3 (T07) + Stream-F (Wave 1B) — Realm in terminal state
    // (`ck.realm.tombstone` OR `ck.realm.destroy` applied) refuses every
    // non-audit-class write. Spec `realm-and-space.md` §2.5 / §2.5.1.
    // The projection lock is poison-free (`state::Mutex`), so this check is
    // always evaluated — a terminal Realm can never be written to because a
    // lock failure defaulted the answer to "not terminal" (fail-open).
    let realm_terminal = state
        .projection
        .lock()
        .expect("projection lock")
        .realm_is_in_terminal_state(&realm_id);
    if let Some((code, reason)) = terminal_realm_check(realm_terminal, &kind) {
        return Err(event_validation_error(
            error_http_status(code),
            code.as_str(),
            reason,
        ));
    }
    // Spec realm-and-space.md §2.6 — `ck.realm.create` is the genesis
    // event for both the Realm metadata cell AND the creator's first
    // member-state cell. The reducer MUST treat `created_by`
    // as already-a-member when admitting this event; otherwise spec-
    // correct clients can never bootstrap a Realm through the canonical
    // event-submission path. The submit_event commit path (below)
    // materialises the member set in state.realms immediately after
    // store.put succeeds, so any follow-up facet event in the same
    // session naturally passes the regular realm_has_member check.
    let is_realm_create_bootstrap = kind == "ck.realm.create"
        && realm_create_actor_is_creator(object, &session.actor)
        && !realm_exists_in_index(state, &realm_id);
    let is_invite_acceptance_join =
        member_join_accepts_pending_invite(state, object, &session.actor, &realm_id).await;
    // A private cross-PS invite delivery (`POST /_cokret/peer/invites`) submits
    // the inviter-signed `ck.invite.create` on the *recipient* PS so the local
    // subject can list + accept it. That realm lives on the inviter's PS, so the
    // recipient PS has no member record for it — yet it MUST still record the
    // pending invite for its subject. Admit `ck.invite.create` from its own
    // inviter into a realm this PS does not host (spec invite-addressing.md §5).
    let is_foreign_invite_delivery = kind == "ck.invite.create"
        && invite_create_actor_is_inviter(object, &session.actor)
        && !realm_exists_in_index(state, &realm_id);
    if !is_realm_create_bootstrap
        && !is_invite_acceptance_join
        && !is_foreign_invite_delivery
        && !realm_has_member(state, &realm_id, &session.actor).await
    {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "capability_denied",
            "actor is not a member of the event Realm",
        ));
    }
    require_object_field(object, "payload")?;
    // CKP-0007 (spec b7d35be) — hard-reject any wire payload that carries a
    // field listed in `forbidden-wire-fields.json` (sourced from the SDK's
    // `is_forbidden_wire_field`). Receivers MUST refuse the legacy field
    // names outright; no compat path. Spec floor 2b0d70d.
    if let Some(field) = first_forbidden_wire_field(object.get("payload")) {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "forbidden_wire_field",
            format!(
                "payload carries forbidden wire field {field:?} \
                 (spec/v1/artifacts/registry/forbidden-wire-fields.json)"
            ),
        ));
    }
    validate_event_schema_and_payload(state, &kind, &schema_id, envelope, object)?;
    if kind == kinds::CK_MEMBER_IDENTITY_UPDATE {
        validate_member_identity_proof(state, object.get("payload").unwrap_or(&Value::Null))?;
    }
    validate_audit_accessed_payload(&kind, object)?;
    // Round R2/R3 (T08) — cross_domain replay defence MUST run BEFORE the
    // signature check (verified below in `validate_event_proofs`). Aggressive
    // mode: payload missing the new required fields surfaces as
    // schema_violation here; payload with mismatched trust_domain surfaces as
    // the registered `cross_domain_replay_rejected` (409) code.
    if kind == "ck.cross_signing.reset" {
        let payload = object.get("payload").cloned().unwrap_or(Value::Null);
        if let Err((code, reason)) =
            cross_signing_reset_replay_check(&payload, &event_id, &state.config.trust_domain)
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
    if kind == "ck.realm.policy_components" {
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
    // `ck.realm.seal.submit` payload shape used by federation push;
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
    let authorized_refs = event_semantic_refs(object, state, MAX_EVENT_REFS)?;
    let canonical_bytes = event_canonical_bytes(envelope)?;
    let canonical_digest = event_digest(&canonical_bytes);
    validate_strand_watch_audit_pair(
        state,
        &kind,
        object,
        &event_id,
        &actor_id,
        &canonical_digest,
    )
    .await?;
    validate_event_proofs(object, state, session, &actor_id, &canonical_digest).await?;
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

pub(super) async fn projected_media_plaintext_service_present(
    state: &AppState,
    realm_id: &str,
    payload: &Value,
) -> bool {
    payload_declares_media_plaintext_service(payload, &state.config.service_did)
        || realm_allows_plaintext_service(state, realm_id).await
}

pub(crate) fn payload_declares_media_plaintext_service(payload: &Value, service_did: &str) -> bool {
    payload
        .pointer("/plaintext_visible_services")
        .and_then(Value::as_array)
        .is_some_and(|services| {
            services.iter().any(|service| match service {
                Value::String(value) => value == service_did || value == "media_plaintext",
                Value::Object(object) => {
                    let purpose_matches =
                        object.get("purpose").and_then(Value::as_str) == Some("media_plaintext");
                    let service_matches = object
                        .get("service_did")
                        .or_else(|| object.get("did"))
                        .and_then(Value::as_str)
                        .is_none_or(|value| value == service_did);
                    purpose_matches && service_matches
                }
                _ => false,
            })
        })
}

pub(super) fn projected_mls_governance_binding_covers_policy_root(
    state: &AppState,
    realm_id: &str,
    payload: &Value,
) -> bool {
    let expected_policy_root = payload_mls_governance_policy_root(payload);
    let Some(projection) = state.projection.lock().ok() else {
        return expected_policy_root.is_some();
    };
    let mut observed_realm_mls_cell = false;
    for (cell, cell_state) in &projection.cells {
        let cell_id = cell.as_str();
        let is_mls_cell = cell_id.contains("ck.component.mls.epoch.v1")
            || cell_id.contains("ck.component.mls_epoch.v1")
            || cell_id.contains("ck.component.covered_seals.v1");
        if !is_mls_cell {
            continue;
        }
        let cokret_sdk::lattice::CellState::Value(value) = cell_state else {
            continue;
        };
        if !value_targets_realm(value, realm_id) {
            continue;
        }
        observed_realm_mls_cell = true;
        if mls_governance_value_covers_policy_root(value, expected_policy_root) {
            return true;
        }
    }
    !observed_realm_mls_cell && expected_policy_root.is_some()
}

/// SEC-03 — project the `discussion_metadata_digest` the realm's current MLS
/// epoch governance binding covers, so [`realm_policy_components_check`] can
/// recompute the `media_service_decrypts` fact and reject a stale / forged
/// binding (`media-service-binding.md` §8.2 rule 5). Mirrors the cell-selection
/// logic of [`projected_mls_governance_binding_covers_policy_root`]; returns the
/// digest from the first realm-targeting MLS cell that carries one, or `None`
/// when no projected binding advertises a digest (in which case the digest gate
/// is skipped and only policy_root coverage applies).
fn projected_mls_governance_binding_metadata_digest(
    state: &AppState,
    realm_id: &str,
) -> Option<String> {
    let projection = state.projection.lock().ok()?;
    for (cell, cell_state) in &projection.cells {
        let cell_id = cell.as_str();
        let is_mls_cell = cell_id.contains("ck.component.mls.epoch.v1")
            || cell_id.contains("ck.component.mls_epoch.v1")
            || cell_id.contains("ck.component.covered_seals.v1");
        if !is_mls_cell {
            continue;
        }
        let cokret_sdk::lattice::CellState::Value(value) = cell_state else {
            continue;
        };
        if !value_targets_realm(value, realm_id) {
            continue;
        }
        if let Some(digest) = mls_governance_value_discussion_metadata_digest(value) {
            return Some(digest.to_owned());
        }
    }
    None
}

/// SEC-03 — read the `discussion_metadata_digest` from a projected MLS cell
/// value, checking the same binding sub-objects that
/// [`mls_governance_value_covers_policy_root`] inspects for `policy_root`.
fn mls_governance_value_discussion_metadata_digest(value: &Value) -> Option<&str> {
    [
        value.pointer("/governance_binding/discussion_metadata_digest"),
        value.pointer("/mls_governance_binding/discussion_metadata_digest"),
        value.pointer("/discussion_metadata_digest"),
    ]
    .into_iter()
    .flatten()
    .find_map(|candidate| {
        candidate
            .as_str()
            .filter(|digest| !digest.trim().is_empty())
    })
}

fn payload_mls_governance_policy_root(payload: &Value) -> Option<&str> {
    payload
        .pointer("/mls_governance_binding/policy_root")
        .or_else(|| payload.pointer("/governance_binding/policy_root"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

fn value_targets_realm(value: &Value, realm_id: &str) -> bool {
    if value.get("space_id").is_some() {
        return false;
    }
    value
        .get("realm_id")
        .and_then(Value::as_str)
        .is_none_or(|value| value == realm_id)
}

fn mls_governance_value_covers_policy_root(
    value: &Value,
    expected_policy_root: Option<&str>,
) -> bool {
    let candidates = [
        value.pointer("/governance_binding/policy_root"),
        value.pointer("/mls_governance_binding/policy_root"),
        value.pointer("/policy_root"),
    ];
    candidates.iter().flatten().any(|candidate| {
        candidate.as_str().is_some_and(|policy_root| {
            !policy_root.trim().is_empty()
                && expected_policy_root.is_none_or(|expected| expected == policy_root)
        })
    })
}

pub(super) fn validate_event_critical_features(
    object: &serde_json::Map<String, Value>,
) -> Result<(), EventValidationError> {
    let supported = [
        "ck.event_envelope.v1",
        "ck.profile.core_event_store.v1",
        "ck.proof.event_digest.v1",
    ];
    for key in ["crit", "critical", "critical_features"] {
        let Some(value) = object.get(key) else {
            continue;
        };
        let features = match value {
            Value::Array(values) => values
                .iter()
                .map(|value| value.as_str().map(ToOwned::to_owned))
                .collect::<Option<Vec<_>>>(),
            Value::String(value) => Some(vec![value.clone()]),
            _ => None,
        }
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_param",
                "critical features must be strings",
            )
        })?;
        for feature in features {
            if !supported.contains(&feature.as_str()) {
                return Err(event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "unsupported_critical_feature",
                    "unknown critical Event feature is not supported",
                ));
            }
        }
    }
    let Some(critical_extensions) = object
        .get("requirements")
        .and_then(|requirements| requirements.get("critical_extensions"))
    else {
        return Ok(());
    };
    let Some(critical_extensions) = critical_extensions.as_array() else {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "requirements.critical_extensions must be an array",
        ));
    };
    for extension in critical_extensions {
        let (id, fail_closed) = match extension {
            Value::String(id) => (id.as_str(), true),
            Value::Object(object) => {
                let id = object.get("id").and_then(Value::as_str).ok_or_else(|| {
                    event_validation_error(
                        StatusCode::BAD_REQUEST,
                        "schema_violation",
                        "requirements.critical_extensions[].id is required",
                    )
                })?;
                let fail_closed = object
                    .get("fail_closed")
                    .and_then(Value::as_bool)
                    .unwrap_or(true);
                (id, fail_closed)
            }
            _ => {
                return Err(event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    "requirements.critical_extensions entries must be strings or objects",
                ));
            }
        };
        if fail_closed && !supported.contains(&id) {
            return Err(event_validation_error(
                StatusCode::NOT_IMPLEMENTED,
                "unsupported_feature",
                "unknown requirements.critical_extensions entry is not supported",
            ));
        }
    }
    Ok(())
}

const CK_AUDIT_ACCESSED: &str = "ck.audit.accessed";
const CK_MODERATION_FRANKING_PROOF: &str = "ck.moderation.franking_proof";
const MANAGE_OTHERS_AUDIT_MISSING: &str = "manage_others_audit_missing";

pub(crate) async fn append_encrypted_message_franking(
    state: &AppState,
    parsed: &ValidatedEventEnvelope,
    envelope: &Value,
) {
    if parsed.kind != "ck.message.create" {
        return;
    }
    let Some(policy) = audit_disclosure_policy_for_realm(state, &parsed.realm_id).await else {
        return;
    };
    if policy.get("enabled").and_then(Value::as_bool) == Some(false) {
        return;
    }
    let Some(ciphertext_digest) = encrypted_message_ciphertext_digest(envelope) else {
        return;
    };
    let mut proof = json!({
        "kind": CK_MODERATION_FRANKING_PROOF,
        "realm_id": parsed.realm_id,
        "target_event_id": parsed.event_id,
        "sender_did": parsed.actor_id,
        "receiving_service_did": state.config.service_did,
        "ciphertext_digest": ciphertext_digest,
        "event_canonical_digest": parsed.canonical_digest,
        "timestamp": now(),
        "audit_disclosure_policy": {
            "agent_id": policy.get("agent_id").cloned().unwrap_or(Value::Null),
            "trigger": policy.get("trigger").cloned().unwrap_or(Value::Null),
        },
    });
    let proof_digest = franking_proof_digest(&proof);
    proof["proof_digest"] = json!(proof_digest);
    append_audit_log(
        state,
        Some(&parsed.actor_id),
        CK_MODERATION_FRANKING_PROOF,
        proof,
        "accepted",
    )
    .await;
}

fn encrypted_message_ciphertext_digest(envelope: &Value) -> Option<String> {
    for pointer in [
        "/payload/encrypted_content/digests/ciphertext",
        "/payload/encrypted_content/ciphertext_digest",
        "/payload/ciphertext_digest",
    ] {
        if let Some(digest) = envelope.pointer(pointer).and_then(Value::as_str)
            && is_valid_sha256_digest(digest)
        {
            return Some(digest.to_owned());
        }
    }
    envelope
        .pointer("/payload/encrypted_content/ciphertext")
        .and_then(Value::as_str)
        .map(|ciphertext| cokret_sdk::canonical::sha256_digest(ciphertext.as_bytes()))
}

async fn audit_disclosure_policy_for_realm(state: &AppState, realm_id: &str) -> Option<Value> {
    state
        .persistence
        .events()
        .snapshot_all()
        .await
        .ok()?
        .into_iter()
        .filter(|record| {
            record.kind == kinds::CK_REALM_CREATE
                && canonical_realm_id_for_record(record).as_deref() == Some(realm_id)
        })
        .rev()
        .find_map(|record| {
            record
                .envelope
                .pointer("/payload/object/audit_disclosure_policy")
                .or_else(|| record.envelope.pointer("/payload/audit_disclosure_policy"))
                .cloned()
        })
}

fn franking_proof_digest(proof: &Value) -> String {
    let material = json!({
        "kind": proof.get("kind").and_then(Value::as_str).unwrap_or(CK_MODERATION_FRANKING_PROOF),
        "target_event_id": proof.get("target_event_id").and_then(Value::as_str).unwrap_or_default(),
        "sender_did": proof.get("sender_did").and_then(Value::as_str).unwrap_or_default(),
        "receiving_service_did": proof.get("receiving_service_did").and_then(Value::as_str).unwrap_or_default(),
        "ciphertext_digest": proof.get("ciphertext_digest").and_then(Value::as_str).unwrap_or_default(),
        "event_canonical_digest": proof.get("event_canonical_digest").and_then(Value::as_str).unwrap_or_default(),
    });
    let bytes = serde_json::to_vec(&material).unwrap_or_default();
    cokret_sdk::canonical::sha256_digest(&bytes)
}

fn validate_audit_accessed_payload(
    kind: &str,
    object: &serde_json::Map<String, Value>,
) -> Result<(), EventValidationError> {
    if kind != CK_AUDIT_ACCESSED {
        return Ok(());
    }
    let payload = object
        .get("payload")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "ck.audit.accessed payload must be an object",
            )
        })?;
    const ALLOWED: &[&str] = &[
        "access_kind",
        "accessed_at",
        "cell_head_after",
        "cell_head_before",
        "paired_event_digest",
        "paired_event_id",
        "purpose",
        "ryw_required",
        "target_actor_id",
        "target_cell_id",
        "target_ref",
        "writer_did",
    ];
    if payload.keys().any(|key| !ALLOWED.contains(&key.as_str())) {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "ck.audit.accessed payload contains an unknown field",
        ));
    }
    let access_kind = required_payload_string(payload, "access_kind")?;
    if !matches!(
        access_kind.as_str(),
        "watch_set_others"
            | "watch_audit_read"
            | "e2ee_plaintext_release"
            | "join_application_review"
            | "policy_audit_read"
            | "other"
    ) {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "ck.audit.accessed access_kind is invalid",
        ));
    }
    let writer_did = required_payload_string(payload, "writer_did")?;
    validate_did(&writer_did).map_err(|_| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "ck.audit.accessed writer_did must be a DID",
        )
    })?;
    if object.get("actor_id").and_then(Value::as_str) != Some(writer_did.as_str()) {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "actor_session_mismatch",
            "ck.audit.accessed writer_did must match actor_id",
        ));
    }
    let target_ref = required_payload_string(payload, "target_ref")?;
    if !target_ref.starts_with("ck:") {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "ck.audit.accessed target_ref must be a typed object ref",
        ));
    }
    if required_payload_string(payload, "purpose")?
        .trim()
        .is_empty()
    {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "ck.audit.accessed purpose must be non-empty",
        ));
    }
    let accessed_at = required_payload_string(payload, "accessed_at")?;
    DateTime::parse_from_rfc3339(&accessed_at).map_err(|_| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "ck.audit.accessed accessed_at must be RFC3339",
        )
    })?;
    match access_kind.as_str() {
        "watch_set_others" => {
            validate_watch_audit_payload_fields(payload)?;
            for field in ["paired_event_id", "paired_event_digest"] {
                let value = required_payload_string(payload, field)?;
                if (field == "paired_event_id" && !is_valid_event_id(&value))
                    || (field == "paired_event_digest" && !is_valid_sha256_digest(&value))
                {
                    return Err(event_validation_error(
                        StatusCode::BAD_REQUEST,
                        "schema_violation",
                        "ck.audit.accessed paired event fields are invalid",
                    ));
                }
            }
            for field in ["cell_head_before", "cell_head_after"] {
                if !payload.get(field).is_some_and(|value| {
                    value.is_null() || value.as_str().is_some_and(is_valid_sha256_digest)
                }) {
                    return Err(event_validation_error(
                        StatusCode::BAD_REQUEST,
                        "schema_violation",
                        "ck.audit.accessed cell heads must be null or sha256 digest",
                    ));
                }
            }
        }
        "watch_audit_read" => {
            validate_watch_audit_payload_fields(payload)?;
        }
        _ => {}
    }
    Ok(())
}

fn validate_watch_audit_payload_fields(
    payload: &serde_json::Map<String, Value>,
) -> Result<(), EventValidationError> {
    let target_actor = required_payload_string(payload, "target_actor_id")?;
    validate_did(&target_actor).map_err(|_| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "ck.audit.accessed target_actor_id must be a DID",
        )
    })?;
    let target_cell_id = required_payload_string(payload, "target_cell_id")?;
    if !target_cell_id.starts_with("ck:cell:") {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "ck.audit.accessed target_cell_id must use ck:cell:",
        ));
    }
    Ok(())
}

fn required_payload_string(
    payload: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<String, EventValidationError> {
    payload
        .get(field)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("ck.audit.accessed requires {field}"),
            )
        })
}

async fn validate_strand_watch_audit_pair(
    state: &AppState,
    kind: &str,
    object: &serde_json::Map<String, Value>,
    event_id: &str,
    actor_id: &str,
    canonical_digest: &str,
) -> Result<(), EventValidationError> {
    if kind != kinds::CK_STRAND_WATCH_SET {
        return Ok(());
    }
    let payload = object
        .get("payload")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "strand watch payload must be an object",
            )
        })?;
    let target_actor = payload
        .get("watcher_actor_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "strand watch payload requires watcher_actor_id",
            )
        })?;
    if target_actor == actor_id {
        return Ok(());
    }
    if payload.get("level").and_then(Value::as_str) == Some("muted")
        || payload
            .get("level_public")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    {
        return Err(event_validation_error(
            StatusCode::PRECONDITION_FAILED,
            MANAGE_OTHERS_AUDIT_MISSING,
            "manage_others strand watch writes cannot set muted or public levels",
        ));
    }
    let audit_refs = event_refs_with_role(object, "audit_pair")?;
    let Some(audit_ref) = audit_refs.first() else {
        return Err(manage_others_audit_error(
            "cross-actor strand watch writes require refs[role=audit_pair]",
        ));
    };
    if audit_refs.len() != 1 {
        return Err(manage_others_audit_error(
            "cross-actor strand watch writes require exactly one audit_pair ref",
        ));
    }
    let audit_record = state
        .persistence
        .events()
        .get(audit_ref)
        .await
        .map_err(|_| manage_others_audit_error("audit_pair event lookup failed"))?
        .ok_or_else(|| manage_others_audit_error("audit_pair event is not accepted"))?;
    if audit_record.kind != CK_AUDIT_ACCESSED {
        return Err(manage_others_audit_error(
            "audit_pair ref must point to ck.audit.accessed",
        ));
    }
    let audit_payload = audit_record
        .envelope
        .get("payload")
        .and_then(Value::as_object)
        .ok_or_else(|| manage_others_audit_error("audit_pair payload is invalid"))?;
    let strand_id = payload
        .get("strand_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let checks = [
        ("access_kind", "watch_set_others"),
        ("writer_did", actor_id),
        ("target_actor_id", target_actor),
        ("target_ref", strand_id),
        ("paired_event_id", event_id),
        ("paired_event_digest", canonical_digest),
    ];
    for (field, expected) in checks {
        if audit_payload.get(field).and_then(Value::as_str) != Some(expected) {
            return Err(manage_others_audit_error(
                "audit_pair payload does not match the strand watch event",
            ));
        }
    }
    Ok(())
}

fn event_refs_with_role(
    object: &serde_json::Map<String, Value>,
    role: &str,
) -> Result<Vec<String>, EventValidationError> {
    let Some(values) = object.get("refs").and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    let mut refs = Vec::new();
    for value in values {
        let Some(reference) = value.as_object() else {
            continue;
        };
        if reference.get("role").and_then(Value::as_str) == Some(role) {
            let id = reference.get("id").and_then(Value::as_str).ok_or_else(|| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_param",
                    "refs entries require id",
                )
            })?;
            if !is_valid_event_id(id) {
                return Err(event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_param",
                    "audit_pair refs must use ck:event: typed ids",
                ));
            }
            refs.push(id.to_owned());
        }
    }
    Ok(refs)
}

fn manage_others_audit_error(message: impl Into<String>) -> EventValidationError {
    event_validation_error(
        StatusCode::PRECONDITION_FAILED,
        MANAGE_OTHERS_AUDIT_MISSING,
        message,
    )
}

pub(super) fn validate_event_time_fields(
    state: &AppState,
    object: &serde_json::Map<String, Value>,
) -> Result<(), EventValidationError> {
    let created_at_value = object.get("created_at");
    if created_at_value.is_some_and(|value| !value.is_string()) {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "created_at must be a string",
        ));
    }
    match created_at_value.and_then(Value::as_str) {
        Some(value) => canonical::validate_timestamp_canonical(value).map_err(|_| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "invalid_param",
                "created_at must use canonical RFC3339 UTC form",
            )
        })?,
        None if !state.config.development_mode => {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "missing_param",
                "created_at is required in production mode",
            ));
        }
        None => {}
    }

    let hlc_value = object.get("hlc");
    if hlc_value.is_some_and(|value| !value.is_string()) {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "hlc must be a string",
        ));
    }
    match hlc_value.and_then(Value::as_str) {
        Some(value) => {
            Hlc::new(value).map_err(|_| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_param",
                    "hlc must use canonical lower-hex HLC form",
                )
            })?;
        }
        None if !state.config.development_mode => {
            return Err(event_validation_error(
                StatusCode::BAD_REQUEST,
                "missing_param",
                "hlc is required in production mode",
            ));
        }
        None => {}
    }

    Ok(())
}

pub(super) fn validate_event_schema_and_payload(
    state: &AppState,
    kind: &str,
    _schema_id: &str,
    envelope: &Value,
    object: &serde_json::Map<String, Value>,
) -> Result<(), EventValidationError> {
    if !state.config.development_mode {
        let registry = cokret_sdk::schema::schema_registry_from_default_spec_artifacts()
            .map_err(|_| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    "event schema registry could not be loaded",
                )
            })?
            .ok_or_else(|| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    "event schema registry is unavailable",
                )
            })?;
        registry
            .validate_value("ck.schema.event.v1", envelope)
            .map_err(|_| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    "event envelope violates ck.schema.event.v1",
                )
            })?;
    }

    let payload = object.get("payload").ok_or_else(|| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "missing_param",
            "event payload is required",
        )
    })?;
    // R3.2 wire-breaking deny validators (MIU-SOL-1 / HC-SOL-3). These run
    // ahead of the registered payload-schema validator so a forbidden
    // field surfaces the precise R3.2 reason code rather than a generic
    // `schema_violation` from the SDK catalog.
    validate_r3_2_wire_shape(kind, payload)?;
    if kind == kinds::CK_CONFLICT_REPAIR {
        return validate_conflict_repair_event_payload(payload);
    }
    if matches!(
        kind,
        kinds::CK_SPACE_CONTAINER_ARCHIVE
            | kinds::CK_SPACE_CONTAINER_RESTORE
            | kinds::CK_SPACE_CONTAINER_TOMBSTONE
    ) {
        return validate_space_container_lifecycle_payload(payload);
    }
    cokret_sdk::schema::event_payload_validator_catalog()
        .validate_payload(kind, payload)
        .map_err(|error| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("event payload violates the registered payload schema: {error}"),
            )
        })?;
    validate_realm_create_policy_constraints(kind, payload)?;
    Ok(())
}

/// R3.2 (cokret-spec @ b56cab1) — wire-breaking deny validators applied on
/// the event ingest path.
///
/// - MIU-SOL-1: `ck.member.identity.update` payloads MUST NOT carry the removed handle fields
///   (`primary_handle` / `handles[]` / `verified_handle`).
/// - HC-SOL-3: message event payloads carrying mention references MUST use the v2 shape
///   (`subject_id` authoritative); the legacy `subject` / `handle` / `display_snapshot` shape is
///   rejected.
///
/// Each maps a [`crate::wire_validators::WireRejection`] to a
/// `schema_violation`-class [`EventValidationError`] carrying the precise
/// R3.2 reason code.
fn validate_r3_2_wire_shape(kind: &str, payload: &Value) -> Result<(), EventValidationError> {
    if kind == kinds::CK_MEMBER_IDENTITY_UPDATE {
        crate::wire_validators::member_identity::validate_member_identity_update_payload(payload)
            .map_err(wire_rejection_to_validation_error)?;
    }
    if matches!(kind, kinds::CK_MESSAGE_CREATE | kinds::CK_MESSAGE_REVISE)
        && let Some(content) = payload.get("content")
    {
        crate::wire_validators::mention::validate_content_mention_references(content)
            .map_err(wire_rejection_to_validation_error)?;
    }
    Ok(())
}

fn wire_rejection_to_validation_error(
    rejection: crate::wire_validators::WireRejection,
) -> EventValidationError {
    event_validation_error(StatusCode::BAD_REQUEST, rejection.reason, rejection.message)
}

pub(super) fn validate_member_identity_proof(
    state: &AppState,
    payload: &Value,
) -> Result<(), EventValidationError> {
    let Some(identity_payload) = payload.get("identity_payload") else {
        return Ok(());
    };
    let Some(member_identity_value) = identity_payload.get("member_identity") else {
        if identity_payload.get("encrypted_payload").is_some() {
            return Err(event_validation_error(
                StatusCode::NOT_IMPLEMENTED,
                "unsupported_feature",
                "encrypted MemberIdentity proof verification is not wired; refusing fail-closed",
            ));
        }
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "identity_payload must carry member_identity or encrypted_payload",
        ));
    };
    let identity: cokret_sdk::MemberIdentity =
        serde_json::from_value(member_identity_value.clone()).map_err(|error| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                format!("MemberIdentity payload shape is invalid: {error}"),
            )
        })?;
    let payload_realm = payload.get("realm_id").and_then(Value::as_str);
    let payload_actor = payload.get("actor_id").and_then(Value::as_str);
    if payload_realm != Some(identity.realm_id.as_str())
        || payload_actor != Some(identity.actor_id.as_str())
    {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "MemberIdentity realm_id/actor_id must match the update payload subject",
        ));
    }
    let canonical_bytes = identity.canonical_payload_bytes().map_err(|error| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            format!("MemberIdentity canonical payload failed: {error}"),
        )
    })?;
    let payload_digest = identity.canonical_payload_sha256().map_err(|error| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            format!("MemberIdentity payload digest failed: {error}"),
        )
    })?;
    if identity.proof.payload_digest.as_str() != payload_digest {
        crate::metrics::record_digest_mismatch("member_identity_payload_digest");
        return Err(event_validation_error(
            StatusCode::CONFLICT,
            "proof_event_digest_mismatch",
            "MemberIdentityProof.payload_digest does not match the canonical payload",
        ));
    }
    if !matches!(
        identity.proof.signature_algorithm,
        cokret_sdk::MemberIdentitySignatureAlgorithm::Ed25519
    ) {
        return Err(event_validation_error(
            StatusCode::NOT_IMPLEMENTED,
            "unsupported_feature",
            "only Ed25519 MemberIdentityProof.signature_algorithm is supported",
        ));
    }
    crate::jws_verify::validate_verification_method_controller(
        identity.subject_id.as_str(),
        &identity.proof.verification_method,
    )
    .map_err(|error| {
        event_validation_error(
            StatusCode::FORBIDDEN,
            "proof_invalid",
            format!("MemberIdentity proof controller mismatch: {error}"),
        )
    })?;
    let public_key =
        crate::jws_verify::resolve_ed25519_pubkey(state, &identity.proof.verification_method)
            .map_err(|error| {
                event_validation_error(
                    StatusCode::FORBIDDEN,
                    "proof_invalid",
                    format!("MemberIdentity proof verification key resolution failed: {error}"),
                )
            })?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(identity.proof.signature.as_bytes())
        .map_err(|error| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "proof_invalid",
                format!("MemberIdentity proof signature is not base64url: {error}"),
            )
        })?;
    let signature_array: [u8; 64] = signature_bytes.try_into().map_err(|_| {
        event_validation_error(
            StatusCode::BAD_REQUEST,
            "proof_invalid",
            "MemberIdentity proof signature must be 64 bytes",
        )
    })?;
    let signature = ed25519_dalek::Signature::from_bytes(&signature_array);
    public_key
        .verify(&canonical_bytes, &signature)
        .map_err(|error| {
            event_validation_error(
                StatusCode::FORBIDDEN,
                "proof_invalid",
                format!("MemberIdentity proof signature verification failed: {error}"),
            )
        })
}

fn validate_conflict_repair_event_payload(payload: &Value) -> Result<(), EventValidationError> {
    let Some(object) = payload.as_object() else {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "conflict repair payload must be an object",
        ));
    };
    let cell_id = object
        .get("cell_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "conflict repair payload requires cell_id",
            )
        })?;
    if !cell_id.starts_with("ck:cell:") {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "conflict repair cell_id must use ck:cell:",
        ));
    }
    let heads = object
        .get("conflict_heads")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "conflict repair payload requires conflict_heads",
            )
        })?;
    if heads.len() < 2
        || heads
            .iter()
            .any(|head| head.as_str().is_none_or(|value| value.trim().is_empty()))
    {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "conflict repair conflict_heads must contain at least two non-empty strings",
        ));
    }
    if object
        .get("recovery_capability_ref")
        .and_then(Value::as_str)
        .is_none_or(|value| value.trim().is_empty())
    {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "conflict repair payload requires recovery_capability_ref",
        ));
    }
    if !object.contains_key("winner_value") {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "conflict repair payload requires winner_value",
        ));
    }
    Ok(())
}

fn validate_realm_create_policy_constraints(
    kind: &str,
    payload: &Value,
) -> Result<(), EventValidationError> {
    if kind != kinds::CK_REALM_CREATE {
        return Ok(());
    }
    let Some(object) = payload.get("object").and_then(Value::as_object) else {
        return Ok(());
    };
    let history_visibility = object
        .get("history_visibility")
        .and_then(Value::as_str)
        .unwrap_or("joined");
    let encryption_profile = object
        .get("encryption_profile")
        .and_then(Value::as_str)
        .unwrap_or("none");
    if history_visibility == "world_readable" && encryption_profile != "none" {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "incompatible_history_with_encryption",
            "world_readable history requires encryption_profile=none",
        ));
    }
    if history_visibility == "restricted"
        && object
            .get("history_sharing_policy")
            .and_then(Value::as_object)
            .is_none()
    {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "history_sharing_policy_missing",
            "restricted history_visibility requires an effective history_sharing_policy",
        ));
    }
    Ok(())
}

fn validate_space_container_lifecycle_payload(payload: &Value) -> Result<(), EventValidationError> {
    let Some(object) = payload.as_object() else {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "space lifecycle payload must be an object",
        ));
    };
    let target = object
        .get("space_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            event_validation_error(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "space lifecycle payload requires space_id",
            )
        })?;
    if validate_space_id(target).is_err() {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "space lifecycle payload space_id must use ck:space:",
        ));
    }
    if object.get("target_ref").is_some() {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "space lifecycle payload must use space_id, not target_ref",
        ));
    }
    Ok(())
}

pub(super) fn event_requirements_schema_id(
    state: &AppState,
    object: &serde_json::Map<String, Value>,
) -> Result<String, EventValidationError> {
    let canonical_schema_id = object
        .get("requirements")
        .and_then(|requirements| requirements.get("schema"))
        .and_then(Value::as_array)
        .and_then(|schemas| schemas.first())
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    if !state.config.development_mode && canonical_schema_id.is_none() {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "missing_param",
            "requirements.schema[] is required in production mode",
        ));
    }
    let schema_id = canonical_schema_id
        .or_else(|| {
            object
                .get("schema_id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| "ck.schema.event.v1".to_owned());
    if !schema_id.starts_with("ck.schema.") || !artifacts::schema_ids().contains(&schema_id) {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "unknown_schema",
            "event schema_id is not in the cokret-spec schema registry",
        ));
    }
    Ok(schema_id)
}

fn validate_event_audience_fields(
    object: &serde_json::Map<String, Value>,
    state: &AppState,
    session: &SessionRecord,
) -> Result<(), EventValidationError> {
    if let Some(audience) = event_string_field(object, &["audience"])
        && audience != state.config.service_did
    {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "audience_mismatch",
            "event audience must bind to this service DID",
        ));
    }
    if let Some(domain) = event_string_field(object, &["domain"])
        && domain != state.config.service_did
    {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "domain_mismatch",
            "event domain must bind to this service DID",
        ));
    }
    if let Some(device_id) = event_string_field(object, &["device_id"])
        && device_id != session.device_id
    {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "device_session_mismatch",
            "event device_id must match the bearer session device",
        ));
    }
    Ok(())
}

pub(super) async fn validate_event_proofs(
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
        // envelope digest. Dev-only: also accept the payload-only sha256 form
        // so test fixtures keep round-tripping. Production never falls back.
        let payload_only_hash_accept = if is_dev_proof {
            object.get("payload").map(|payload| {
                let bytes = canonical::canonical_json_bytes(payload).unwrap_or_default();
                cokret_sdk::canonical::sha256_digest(&bytes)
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
        if verification_method != actor_id
            && !verification_method.starts_with(&format!("{actor_id}#"))
        {
            return Err(event_validation_error(
                StatusCode::FORBIDDEN,
                "invalid_proof",
                "proof verification method must be rooted in actor_id",
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
            let proof_binding_bytes = event_proof_binding_bytes(
                &proof_event_digest,
                actor_id,
                &verification_method,
                &created_at,
                proof_object,
            )?;
            // High-risk path: enforce DID document freshness before event
            // proof verification (fail-closed-on-stale). Stale or missing
            // evidence must not be used for signature verification.
            let actor_id = cokret_sdk::Did::new(actor_id.to_owned()).map_err(|error| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_proof",
                    format!("event proof actor_id is not a valid DID: {error}"),
                )
            })?;
            crate::jws_verify::enforce_high_risk_did_freshness(state, &actor_id)
                .await
                .map_err(|reason| {
                    tracing::debug!(%reason, "event proof DID freshness gate failed");
                    event_validation_error(
                        StatusCode::BAD_REQUEST,
                        "stale_did_document",
                        "event proof DID document is stale or unavailable for verification",
                    )
                })?;
            crate::jws_verify::verify_jws_ed25519(
                &proof_binding_bytes,
                &jws,
                &verification_method,
                actor_id.as_str(),
                state,
            )
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

fn event_proof_binding_bytes(
    event_digest: &str,
    actor_id: &str,
    verification_method: &str,
    created_at: &str,
    proof_object: &serde_json::Map<String, Value>,
) -> Result<Vec<u8>, EventValidationError> {
    let mut binding = serde_json::Map::new();
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
