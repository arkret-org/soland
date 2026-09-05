//! `audited-e2ee.md` sections 3-4 — the sealed release session and the four
//! gates a release has to clear: an active binding, the binding's own scope,
//! the session's accepted notice, and a window that does not reach behind the
//! binding activation frontier.

use serde_json::json;

use super::*;

const REALM: &str = "ak:realm:ASReu6ls3Ao5vTK0TGXBCAvLLQChFejCEmN9KaSceZOt";
const APPLET: &str = "ak:applet:01904100-0000-7000-8000-a00000000012";
const SERVICE: &str = "ak:did_core:web:audit.example";
const APPROVER: &str = "ak:did_core:web:approver.example";
const FRONTIER_DIGEST: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const POLICY_DIGEST: &str =
    "sha256:2222222222222222222222222222222222222222222222222222222222222222";
const OTHER_DIGEST: &str =
    "sha256:3333333333333333333333333333333333333333333333333333333333333333";
const SEAL: &str =
    "ak:seal:sha256:4444444444444444444444444444444444444444444444444444444444444444";

fn actor(principal: &str) -> Value {
    serde_json::to_value(arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(principal).unwrap(),
        arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
    )))
    .unwrap()
}

fn realm_scope() -> Value {
    json!({"kind": "realm", "realm_id": REALM})
}

fn apply(
    state: &mut ProjectionState,
    hlc: &ServerHlc,
    kind: &str,
    payload: Value,
) -> (arkret_identifiers::EventId, ProjectionEffect) {
    let (event_id, writes) = projected_cell_writes(kind, REALM, &payload);
    let mut operation_payload = payload;
    operation_payload
        .as_object_mut()
        .expect("audit payload object")
        .insert("event_id".to_owned(), Value::String(event_id.to_string()));
    let operation = make_operation(kind, REALM, operation_payload);
    let effect = state.apply_projected(&operation, &writes, hlc);
    (event_id, effect)
}

fn binding_payload() -> Value {
    json!({
        "realm_id": REALM,
        "effective_scope": realm_scope(),
        "applet_id": APPLET,
        "service_id": SERVICE,
        "purpose_kinds": ["legal_compliance"],
        "allowed_release_modes": ["targeted_evidence_release"],
        "audit_assurance_class": "disclosed_policy",
        "notice_policy": {"audience": "members"},
        "activation_frontier_digest": FRONTIER_DIGEST,
        "first_auditable_epoch": 10,
        "release_window_policy": {
            "retroactive_release": "forbidden",
            "eligibility_basis": "encrypted_after_binding_activation"
        },
        "policy_version_digest": POLICY_DIGEST
    })
}

fn install_active_binding(state: &mut ProjectionState, hlc: &ServerHlc) -> String {
    let (event_id, effect) = apply(
        state,
        hlc,
        arkret_wire::EventKind::AuditAppletBindingCreate.as_str(),
        binding_payload(),
    );
    assert!(
        matches!(effect, ProjectionEffect::AuditBindingProjected { .. }),
        "binding create must project, got {effect:?}"
    );
    arkret_identifiers::AuditBindingId::from_event_id(&event_id).to_string()
}

fn request_payload(binding_id: &str, scope: Value) -> Value {
    json!({
        "binding_id": binding_id,
        "realm_id": REALM,
        "effective_scope": scope,
        "session_state": "request",
        "requested_by": SERVICE,
        "purpose_kind": "legal_compliance",
        "legal_basis_ref": "court-order-2026-1",
        "requested_release_mode": "targeted_evidence_release",
        "request_digest": OTHER_DIGEST,
        "target_refs": ["ak:event:AfJRB2whShXS-ghpXQhgN5u_MsXwor5nNWDxQ6YCfvcf"],
        "occurred_at": "2026-05-02T00:00:00.000Z"
    })
}

fn authorize_payload(binding_id: &str, session_id: &str, request_ref: &str) -> Value {
    json!({
        "session_id": session_id,
        "binding_id": binding_id,
        "realm_id": REALM,
        "effective_scope": realm_scope(),
        "session_state": "authorize",
        "request_ref": request_ref,
        "approver_actor_id": actor(APPROVER),
        "approved_recipient_audit_actor_id": actor(SERVICE),
        "approved_recipient_public_key_ref": "did:web:audit.example#release-1",
        "approved_release_mode": "targeted_evidence_release",
        "notice_policy": {"audience": "members"},
        "expires_at": "2026-05-09T00:00:00.000Z",
        "target_refs": ["ak:event:AfJRB2whShXS-ghpXQhgN5u_MsXwor5nNWDxQ6YCfvcf"],
        "occurred_at": "2026-05-02T00:01:00.000Z"
    })
}

fn notice_payload(binding_id: &str, session_id: &str, authorize_ref: &str) -> Value {
    json!({
        "session_id": session_id,
        "binding_id": binding_id,
        "realm_id": REALM,
        "effective_scope": realm_scope(),
        "session_state": "notice",
        "authorize_ref": authorize_ref,
        "service_id": SERVICE,
        "purpose_kind": "legal_compliance",
        "approved_release_mode": "targeted_evidence_release",
        "approver_actor_id": actor(APPROVER),
        "member_notice_digest": OTHER_DIGEST,
        "target_refs": ["ak:event:AfJRB2whShXS-ghpXQhgN5u_MsXwor5nNWDxQ6YCfvcf"],
        "occurred_at": "2026-05-02T00:02:00.000Z"
    })
}

fn release_payload(binding_id: &str, session_id: &str, notice_ref: &str) -> Value {
    json!({
        "session_id": session_id,
        "binding_id": binding_id,
        "realm_id": REALM,
        "effective_scope": realm_scope(),
        "applet_id": APPLET,
        "service_id": SERVICE,
        "release_mode": "targeted_evidence_release",
        "target_refs": ["ak:event:AfJRB2whShXS-ghpXQhgN5u_MsXwor5nNWDxQ6YCfvcf"],
        "seal_ref": SEAL,
        "approver_actor_id": actor(APPROVER),
        "notice_ref": notice_ref,
        "purpose_kind": "legal_compliance",
        "legal_basis_ref": "court-order-2026-1",
        "policy_version_digest": POLICY_DIGEST,
        "eligibility_proof": {
            "binding_activation_frontier_digest": FRONTIER_DIGEST,
            "first_auditable_epoch": 10,
            "policy_snapshot_digest": POLICY_DIGEST,
            "target_eligibility_digest": OTHER_DIGEST
        },
        "wrapped_material_digest": [OTHER_DIGEST],
        "released_at": "2026-05-02T00:03:00.000Z"
    })
}

/// Walk the whole chain once: binding, request, authorize, notice, release.
fn noticed_session(state: &mut ProjectionState, hlc: &ServerHlc) -> (String, String, String) {
    let binding_id = install_active_binding(state, hlc);
    let (request_event, effect) = apply(
        state,
        hlc,
        arkret_wire::EventKind::AuditSessionRequest.as_str(),
        request_payload(&binding_id, realm_scope()),
    );
    let session_id = match effect {
        ProjectionEffect::AuditSessionProjected { session_id, state } => {
            assert_eq!(state, "request");
            session_id
        }
        other => panic!("session request must project, got {other:?}"),
    };
    assert_eq!(
        session_id,
        arkret_identifiers::AuditSessionId::from_event_id(&request_event).to_string(),
        "the session id is the request Event token retyped"
    );

    let (authorize_event, effect) = apply(
        state,
        hlc,
        arkret_wire::EventKind::AuditSessionAuthorize.as_str(),
        authorize_payload(&binding_id, &session_id, request_event.as_ref()),
    );
    assert!(
        matches!(effect, ProjectionEffect::AuditSessionProjected { ref state, .. } if state == "authorize"),
        "got {effect:?}"
    );

    let (notice_event, effect) = apply(
        state,
        hlc,
        arkret_wire::EventKind::AuditSessionNotice.as_str(),
        notice_payload(&binding_id, &session_id, authorize_event.as_ref()),
    );
    assert!(
        matches!(effect, ProjectionEffect::AuditSessionProjected { ref state, .. } if state == "notice"),
        "got {effect:?}"
    );
    (binding_id, session_id, notice_event.to_string())
}

#[test]
fn a_noticed_session_releases_and_the_manifest_lands_in_its_log() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let (binding_id, session_id, notice_ref) = noticed_session(&mut state, &hlc);

    let (_, effect) = apply(
        &mut state,
        &hlc,
        arkret_wire::EventKind::AuditRelease.as_str(),
        release_payload(&binding_id, &session_id, &notice_ref),
    );
    assert!(
        matches!(
            effect,
            ProjectionEffect::AuditReleaseProjected { session_id: ref id, .. } if *id == session_id
        ),
        "got {effect:?}"
    );
    let log = state
        .cell_value(
            &arkret_identifiers::CellRef::new(format!(
                "ak:cell:{}:{session_id}",
                arkret_wire::CellFamilyId::AUDIT_RELEASE_V1
            ))
            .unwrap(),
        )
        .expect("release log cell")
        .as_array()
        .expect("ordered_log holds an array")
        .len();
    assert_eq!(log, 1, "exactly one release manifest is appended");
}

#[test]
fn a_release_without_the_sessions_notice_is_refused() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let binding_id = install_active_binding(&mut state, &hlc);
    let (request_event, _) = apply(
        &mut state,
        &hlc,
        arkret_wire::EventKind::AuditSessionRequest.as_str(),
        request_payload(&binding_id, realm_scope()),
    );
    let session_id = arkret_identifiers::AuditSessionId::from_event_id(&request_event).to_string();
    apply(
        &mut state,
        &hlc,
        arkret_wire::EventKind::AuditSessionAuthorize.as_str(),
        authorize_payload(&binding_id, &session_id, request_event.as_ref()),
    );

    // Authorized but never noticed: the release names an Event that is not
    // this session's accepted notice.
    let (_, effect) = apply(
        &mut state,
        &hlc,
        arkret_wire::EventKind::AuditRelease.as_str(),
        release_payload(&binding_id, &session_id, request_event.as_ref()),
    );
    assert!(
        matches!(&effect, ProjectionEffect::Rejected { reason } if reason == "audit_release_notice_missing"),
        "got {effect:?}"
    );
}

#[test]
fn a_suspended_binding_is_not_an_audit_authority() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let binding_id = install_active_binding(&mut state, &hlc);
    let (_, effect) = apply(
        &mut state,
        &hlc,
        arkret_wire::EventKind::AuditAppletBindingState.as_str(),
        json!({"binding_id": binding_id, "from": "active", "to": "suspended"}),
    );
    assert!(
        matches!(effect, ProjectionEffect::AuditBindingProjected { .. }),
        "got {effect:?}"
    );

    let (_, effect) = apply(
        &mut state,
        &hlc,
        arkret_wire::EventKind::AuditSessionRequest.as_str(),
        request_payload(&binding_id, realm_scope()),
    );
    assert!(
        matches!(&effect, ProjectionEffect::Rejected { reason } if reason == "audit_release_binding_missing"),
        "got {effect:?}"
    );
}

#[test]
fn a_circle_scope_needs_its_own_circle_scoped_binding() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let binding_id = install_active_binding(&mut state, &hlc);

    let circle_scope = json!({
        "kind": "circle",
        "realm_id": REALM,
        "circle_id": "ak:circle:AfJRB2whShXS-ghpXQhgN5u_MsXwor5nNWDxQ6YCfvcf"
    });
    let (_, effect) = apply(
        &mut state,
        &hlc,
        arkret_wire::EventKind::AuditSessionRequest.as_str(),
        request_payload(&binding_id, circle_scope),
    );
    assert!(
        matches!(&effect, ProjectionEffect::Rejected { reason } if reason == "audit_release_scope_mismatch"),
        "got {effect:?}"
    );
}

#[test]
fn a_release_reaching_behind_the_activation_frontier_is_forbidden() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let (binding_id, session_id, notice_ref) = noticed_session(&mut state, &hlc);

    let mut payload = release_payload(&binding_id, &session_id, &notice_ref);
    // Epoch 9 predates the binding's first_auditable_epoch of 10, and the
    // manifest is otherwise complete, so the only thing wrong with it is that
    // it reaches behind the activation frontier.
    payload["sealed_epoch_range"] = json!({"first_epoch": 9, "last_epoch": 11});
    payload["sealed_by_commit_ref"] =
        json!("ak:event:AfJRB2whShXS-ghpXQhgN5u_MsXwor5nNWDxQ6YCfvcg");
    let (_, effect) = apply(
        &mut state,
        &hlc,
        arkret_wire::EventKind::AuditRelease.as_str(),
        payload,
    );
    assert!(
        matches!(
            &effect,
            ProjectionEffect::Rejected { reason }
                if reason == "audit_release_retroactive_scope_forbidden"
        ),
        "got {effect:?}"
    );
}

#[test]
fn an_epoch_release_without_the_sealing_commit_is_an_invalid_manifest() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let (binding_id, session_id, notice_ref) = noticed_session(&mut state, &hlc);

    let mut payload = release_payload(&binding_id, &session_id, &notice_ref);
    payload["sealed_epoch_range"] = json!({"first_epoch": 10, "last_epoch": 11});
    let (_, effect) = apply(
        &mut state,
        &hlc,
        arkret_wire::EventKind::AuditRelease.as_str(),
        payload,
    );
    assert!(
        matches!(&effect, ProjectionEffect::Rejected { reason } if reason == "audit_release_manifest_invalid"),
        "got {effect:?}"
    );
}

// `audited-e2ee.md` section 6 — remote attestation. The evidence rides inline on
// the release, so these exercise the reducer's own verdict rather than a
// transport check: `_invalid` for untrustworthy evidence, `_mismatch` for valid
// evidence describing some other Realm, service, policy revision or auditor.

const CHAIN_ROOT_BYTES: &[u8] = b"vendor-attestation-root";
const CHAIN_ROOT_B64U: &str = "dmVuZG9yLWF0dGVzdGF0aW9uLXJvb3Q";
const CODE_DIGEST: &str = "sha256:5555555555555555555555555555555555555555555555555555555555555555";
const POLICY_VERSION: &str = "release-service-1.4.2";

fn trust_root_digest() -> String {
    arkret_canonical::sha256_digest(CHAIN_ROOT_BYTES)
}

fn attestation_policy() -> Value {
    json!({
        "trust_root_digests": [trust_root_digest()],
        "allowed_code_digests": [CODE_DIGEST],
        "allowed_policy_versions": [POLICY_VERSION]
    })
}

fn attested_binding_payload() -> Value {
    let mut payload = binding_payload();
    payload["audit_assurance_class"] = json!("attested_hardware");
    payload["attestation_policy"] = attestation_policy();
    payload
}

/// A validity window relative to the release Event's own signed `created_at`,
/// which is the only clock the verdict may depend on. The fixture Event is
/// stamped at build time, so the window is built the same way rather than
/// pinned to a date that would silently expire.
fn window(from_days: i64, to_days: i64) -> Value {
    let now = chrono::Utc::now();
    let stamp = |days: i64| {
        arkret_canonical::format_timestamp_canonical(now + chrono::TimeDelta::days(days))
    };
    json!({"not_before": stamp(from_days), "expires_at": stamp(to_days)})
}

/// Evidence that clears every section 6 check for the fixture binding.
fn attestation() -> Value {
    json!({
        "attestation_id": "ak:attestation:01904100-0000-7000-8000-a00000000099",
        "realm_id": REALM,
        "audit_actor_id": actor(SERVICE),
        "service_id": SERVICE,
        "platform": {"family": "tee_tdx", "vendor": "example", "model": "x1"},
        "measurement": {"code_digest": CODE_DIGEST, "policy_version": POLICY_VERSION},
        "attestation_chains": [{"format": "tdx_quote", "bytes_b64u": CHAIN_ROOT_B64U}],
        "attestation_key": {"algorithm": "Ed25519", "public_key_b64u": "cHVibGljLWtleQ"},
        "verification_method": "did:web:audit.example#attestation-1",
        "validity": window(-1, 30),
        "operator_id": "ak:did_core:web:operator.example",
        "audit_purpose": "compliance_lawful_access",
        "audit_policy_version_digest": POLICY_DIGEST,
        "created_at": "2026-01-01T00:00:00.000Z",
        "proofs": [{
            "kind": "detached_jws",
            "verification_method": "did:web:operator.example#release-1",
            "payload_digest": OTHER_DIGEST,
            "created_at": "2026-01-01T00:00:00.000Z",
            "jws": "ZXlKaGJHY2lPaUpGWkRJMU5URTVJbjA..c2ln"
        }]
    })
}

/// Binding, request, authorize, notice under `attested_hardware`, then a
/// release carrying `mutate`d evidence. Setting the evidence to `null` drops
/// the member entirely.
fn attested_release_effect(mutate: impl FnOnce(&mut Value)) -> ProjectionEffect {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let (binding_event, effect) = apply(
        &mut state,
        &hlc,
        arkret_wire::EventKind::AuditAppletBindingCreate.as_str(),
        attested_binding_payload(),
    );
    assert!(
        matches!(effect, ProjectionEffect::AuditBindingProjected { .. }),
        "attested binding create must project, got {effect:?}"
    );
    let binding_id = arkret_identifiers::AuditBindingId::from_event_id(&binding_event).to_string();

    let (request_event, effect) = apply(
        &mut state,
        &hlc,
        arkret_wire::EventKind::AuditSessionRequest.as_str(),
        request_payload(&binding_id, realm_scope()),
    );
    let session_id = match effect {
        ProjectionEffect::AuditSessionProjected { session_id, .. } => session_id,
        other => panic!("session request must project, got {other:?}"),
    };
    let (authorize_event, _) = apply(
        &mut state,
        &hlc,
        arkret_wire::EventKind::AuditSessionAuthorize.as_str(),
        authorize_payload(&binding_id, &session_id, request_event.as_ref()),
    );
    let (notice_event, _) = apply(
        &mut state,
        &hlc,
        arkret_wire::EventKind::AuditSessionNotice.as_str(),
        notice_payload(&binding_id, &session_id, authorize_event.as_ref()),
    );

    let mut payload = release_payload(&binding_id, &session_id, notice_event.as_ref());
    let mut evidence = attestation();
    mutate(&mut evidence);
    if !evidence.is_null() {
        payload["release_attestation"] = evidence;
    }
    let (_, effect) = apply(
        &mut state,
        &hlc,
        arkret_wire::EventKind::AuditRelease.as_str(),
        payload,
    );
    effect
}

fn rejection_reason(effect: &ProjectionEffect) -> &str {
    match effect {
        ProjectionEffect::Rejected { reason } => reason.as_str(),
        other => panic!("expected a rejection, got {other:?}"),
    }
}

#[test]
fn attested_release_evidence_that_clears_every_check_projects() {
    let effect = attested_release_effect(|_| {});
    assert!(
        matches!(effect, ProjectionEffect::AuditReleaseProjected { .. }),
        "got {effect:?}"
    );
}

#[test]
fn attestation_evidence_the_binding_does_not_trust_is_invalid() {
    // Trust root not in the Realm-declared list.
    let untrusted = attested_release_effect(|evidence| {
        evidence["attestation_chains"] =
            json!([{"format": "tdx_quote", "bytes_b64u": "b3RoZXItcm9vdA"}]);
    });
    assert_eq!(
        rejection_reason(&untrusted),
        "audit_release_attestation_invalid"
    );

    // Validity window closed before the Event's signed created_at.
    let expired = attested_release_effect(|evidence| {
        evidence["validity"] = window(-60, -30);
    });
    assert_eq!(
        rejection_reason(&expired),
        "audit_release_attestation_invalid"
    );

    // A window wider than the 90 days the profile allows.
    let over_long = attested_release_effect(|evidence| {
        evidence["validity"] = window(-100, 100);
    });
    assert_eq!(
        rejection_reason(&over_long),
        "audit_release_attestation_invalid"
    );

    // Measurement outside the binding's allowed set.
    let measurement = attested_release_effect(|evidence| {
        evidence["measurement"]["code_digest"] = json!(OTHER_DIGEST);
    });
    assert_eq!(
        rejection_reason(&measurement),
        "audit_release_attestation_invalid"
    );
    let policy_version = attested_release_effect(|evidence| {
        evidence["measurement"]["policy_version"] = json!("release-service-9.9.9");
    });
    assert_eq!(
        rejection_reason(&policy_version),
        "audit_release_attestation_invalid"
    );

    // software_test_only is a fixture platform and never backs a real release.
    let software = attested_release_effect(|evidence| {
        evidence["platform"]["family"] = json!("software_test_only");
    });
    assert_eq!(
        rejection_reason(&software),
        "audit_release_attestation_invalid"
    );
}

#[test]
fn attestation_evidence_bound_to_other_state_is_a_mismatch() {
    // A different service than the active binding names.
    let service = attested_release_effect(|evidence| {
        evidence["service_id"] = json!("ak:did_core:web:other-audit.example");
    });
    assert_eq!(
        rejection_reason(&service),
        "audit_release_attestation_mismatch"
    );

    // A policy revision other than the binding's.
    let policy = attested_release_effect(|evidence| {
        evidence["audit_policy_version_digest"] = json!(OTHER_DIGEST);
    });
    assert_eq!(
        rejection_reason(&policy),
        "audit_release_attestation_mismatch"
    );

    // An auditor the accepted authorize never approved as recipient.
    let recipient = attested_release_effect(|evidence| {
        evidence["audit_actor_id"] = actor("ak:did_core:web:other-auditor.example");
    });
    assert_eq!(
        rejection_reason(&recipient),
        "audit_release_attestation_mismatch"
    );

    // Evidence issued for another Realm.
    let realm = attested_release_effect(|evidence| {
        evidence["realm_id"] = json!("ak:realm:AfJRB2whShXS-ghpXQhgN5u_MsXwor5nNWDxQ6YCfvcf");
    });
    assert_eq!(
        rejection_reason(&realm),
        "audit_release_attestation_mismatch"
    );
}

#[test]
fn the_assurance_class_decides_whether_evidence_may_be_present() {
    // attested_hardware without evidence has nothing to verify.
    let missing = attested_release_effect(|evidence| {
        *evidence = Value::Null;
    });
    assert_eq!(rejection_reason(&missing), "schema_violation");

    // disclosed_policy is a process guarantee; carrying evidence would claim a
    // controlled-output guarantee the binding never bought.
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let (binding_id, session_id, notice_ref) = noticed_session(&mut state, &hlc);
    let mut payload = release_payload(&binding_id, &session_id, &notice_ref);
    payload["release_attestation"] = attestation();
    let (_, effect) = apply(
        &mut state,
        &hlc,
        arkret_wire::EventKind::AuditRelease.as_str(),
        payload,
    );
    assert_eq!(rejection_reason(&effect), "schema_violation");
}
