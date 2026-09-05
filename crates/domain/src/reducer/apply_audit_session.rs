//! `ak.audit.session.*` and `ak.audit.release` reducers.
//!
//! `audited-e2ee.md` §3-§4 makes the sealed release session the only protocol
//! path to historical key material, and every step of it is a MUST the reducer
//! has to enforce: no active `ak.audit.applet_binding` means no session and no
//! release (`audit_release_binding_missing`); the scope a session or release
//! declares has to be the binding's own (`audit_release_scope_mismatch`); a
//! release without the session's accepted notice is not a released manifest
//! (`audit_release_notice_missing`); and a release that reaches behind the
//! binding activation frontier is forbidden outright
//! (`audit_release_retroactive_scope_forbidden`).
//!
//! Attestation evidence (`ak.schema.audit_release_attestation.v1`) rides inline
//! on the release as `release_attestation` and is verified here against the
//! binding's `attestation_policy` (`audit_release_attestation_invalid`) and
//! against the active binding and accepted authorize
//! (`audit_release_attestation_mismatch`); see §6.

use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_models_collaboration::events_payloads::audit::{
    AuditAttestationPolicy, AuditReleasePayload, AuditSessionPayload, AuditSessionStage,
};
use arkret_models_collaboration::governance::audit::AuditReleaseAttestation;
use chrono::{DateTime, Utc};
use arkret_state::lattice::CellState;
use arkret_wire::cba::{LatticeOpType, ProjectedOp};
use serde_json::Value;

use super::ProjectionState;
use super::effects::ProjectionEffect;
use super::projections::AuditSessionProjection;

/// `audit_assurance_class` value that makes remote attestation load-bearing.
const ATTESTED_HARDWARE_ASSURANCE: &str = "attested_hardware";

fn rejected(reason: &str) -> ProjectionEffect {
    ProjectionEffect::Rejected {
        reason: reason.to_owned(),
    }
}

fn session_cell(session_id: &str) -> Option<arkret_identifiers::CellRef> {
    arkret_identifiers::CellRef::new(format!(
        "ak:cell:{}:{session_id}",
        arkret_wire::CellFamilyId::AUDIT_SESSION_V1
    ))
    .ok()
}

fn release_cell(session_id: &str) -> Option<arkret_identifiers::CellRef> {
    arkret_identifiers::CellRef::new(format!(
        "ak:cell:{}:{session_id}",
        arkret_wire::CellFamilyId::AUDIT_RELEASE_V1
    ))
    .ok()
}

impl ProjectionState {
    /// The immutable binding document, but only while its lifecycle cell says
    /// `active`. A suspended or revoked binding is not an audit authority, so
    /// it reads exactly like an absent one.
    fn active_audit_binding(&self, binding_id: &str) -> Option<&Value> {
        let config = arkret_identifiers::CellRef::new(format!(
            "ak:cell:{}:{binding_id}",
            arkret_wire::CellFamilyId::AUDIT_BINDING_V1
        ))
        .ok()?;
        let lifecycle = arkret_identifiers::CellRef::new(format!(
            "ak:cell:{}:{binding_id}",
            arkret_wire::CellFamilyId::AUDIT_BINDING_STATE_V1
        ))
        .ok()?;
        let active = matches!(
            self.cells.get(&lifecycle),
            Some(CellState::Value(Value::String(state))) if state == "active"
        );
        if !active {
            return None;
        }
        match self.cells.get(&config)? {
            CellState::Value(value) => Some(value),
            CellState::Bottom(_) => None,
        }
    }

    /// `ak.audit.session.request` / `.authorize` / `.notice` / `.close`.
    pub(crate) fn apply_audit_session(&mut self, operation: &Operation) -> ProjectionEffect {
        let payload: AuditSessionPayload = match serde_json::from_value(operation.payload.clone()) {
            Ok(payload) => payload,
            Err(_) => return rejected(arkret_wire::ErrorCode::SCHEMA_VIOLATION),
        };
        if payload.realm_id.as_str() != operation.realm_id.as_str() {
            return rejected(arkret_wire::ReasonCode::AUDIT_RELEASE_SCOPE_MISMATCH);
        }
        let binding_id = payload.binding_id.to_string();
        let Some(binding) = self.active_audit_binding(&binding_id) else {
            return rejected(arkret_wire::ReasonCode::AUDIT_RELEASE_BINDING_MISSING);
        };
        let declared_scope = match serde_json::to_value(&payload.effective_scope) {
            Ok(value) => value,
            Err(_) => return rejected(arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED),
        };
        if binding.get("effective_scope") != Some(&declared_scope) {
            return rejected(arkret_wire::ReasonCode::AUDIT_RELEASE_SCOPE_MISMATCH);
        }

        // `request` derives its session id from its own Event; every later
        // stage names the session it advances.
        let session_id = match payload.session_state {
            AuditSessionStage::Request => {
                if payload.session_id.is_some() {
                    return rejected("audit_session_id_must_be_event_derived");
                }
                arkret_identifiers::AuditSessionId::from_event_id(&operation.context.event_id)
                    .to_string()
            }
            _ => match payload.session_id.as_ref() {
                Some(session_id) => session_id.to_string(),
                None => return rejected(arkret_wire::ErrorCode::SCHEMA_VIOLATION),
            },
        };
        let Some(cell) = session_cell(&session_id) else {
            return rejected(arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED);
        };

        // The registered contract projects the session cell as `transition_to`:
        // the reducer supplies `from` from the frozen pre-state, so only the
        // target stage arrives on the write.
        let target = self
            .projected_cell_writes()
            .iter()
            .find(|write| write.cell_id == cell)
            .and_then(|write| match &write.op {
                ProjectedOp::TransitionTo { to } => to.as_str().map(ToOwned::to_owned),
                _ => None,
            });
        if target.as_deref() != Some(audit_session_stage_str(payload.session_state)) {
            return rejected(arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED);
        }

        let existing = self.audit_sessions.get(&session_id);
        match (payload.session_state, existing) {
            (AuditSessionStage::Request, Some(_)) => {
                return rejected(arkret_wire::ErrorCode::CAS_CONFLICT);
            }
            (AuditSessionStage::Request, None) => {}
            (_, None) => return rejected("audit_session_unresolved"),
            (stage, Some(session)) => {
                if !session.stage.allows_transition_to(stage) || session.stage == stage {
                    return rejected("audit_session_transition_invalid");
                }
                // A later stage may not re-point the session at another
                // binding or widen the scope it was authorized under.
                if session.binding_id != binding_id || session.effective_scope != declared_scope {
                    return rejected(arkret_wire::ReasonCode::AUDIT_RELEASE_SCOPE_MISMATCH);
                }
            }
        }

        let event_id = operation.context.event_id.to_string();
        let notice_ref = match payload.session_state {
            AuditSessionStage::Notice => Some(event_id.clone()),
            _ => existing.and_then(|session| session.notice_ref.clone()),
        };
        let approved_release_mode = payload
            .approved_release_mode
            .or_else(|| existing.and_then(|session| session.approved_release_mode));
        let approved_recipient_audit_actor_id = payload
            .approved_recipient_audit_actor_id
            .as_ref()
            .map(ToString::to_string)
            .or_else(|| {
                existing.and_then(|session| session.approved_recipient_audit_actor_id.clone())
            });
        let projection = AuditSessionProjection {
            session_id: session_id.clone(),
            realm_id: payload.realm_id.to_string(),
            binding_id,
            effective_scope: declared_scope,
            stage: payload.session_state,
            approved_release_mode,
            approved_recipient_audit_actor_id,
            notice_ref,
        };
        self.audit_sessions.insert(session_id.clone(), projection);
        self.cells.insert(
            cell,
            CellState::Value(Value::String(
                audit_session_stage_str(payload.session_state).to_owned(),
            )),
        );
        ProjectionEffect::AuditSessionProjected {
            session_id,
            state: audit_session_stage_str(payload.session_state).to_owned(),
        }
    }

    /// `ak.audit.release` — append one release manifest to the session's
    /// ordered log, but only when the whole authorization chain holds.
    pub(crate) fn apply_audit_release(&mut self, operation: &Operation) -> ProjectionEffect {
        let payload: AuditReleasePayload = match serde_json::from_value(operation.payload.clone()) {
            Ok(payload) => payload,
            Err(_) => return rejected(arkret_wire::ErrorCode::SCHEMA_VIOLATION),
        };
        if payload.realm_id.as_str() != operation.realm_id.as_str() {
            return rejected(arkret_wire::ReasonCode::AUDIT_RELEASE_SCOPE_MISMATCH);
        }
        let binding_id = payload.binding_id.to_string();
        let Some(binding) = self.active_audit_binding(&binding_id).cloned() else {
            return rejected(arkret_wire::ReasonCode::AUDIT_RELEASE_BINDING_MISSING);
        };
        let declared_scope = match serde_json::to_value(&payload.effective_scope) {
            Ok(value) => value,
            Err(_) => return rejected(arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED),
        };
        if binding.get("effective_scope") != Some(&declared_scope) {
            return rejected(arkret_wire::ReasonCode::AUDIT_RELEASE_SCOPE_MISMATCH);
        }

        let session_id = payload.session_id.to_string();
        let Some(session) = self.audit_sessions.get(&session_id) else {
            return rejected(arkret_wire::ReasonCode::AUDIT_RELEASE_NOTICE_MISSING);
        };
        if session.binding_id != binding_id {
            return rejected(arkret_wire::ReasonCode::AUDIT_RELEASE_BINDING_MISSING);
        }
        if session.effective_scope != declared_scope {
            return rejected(arkret_wire::ReasonCode::AUDIT_RELEASE_SCOPE_MISMATCH);
        }
        // audited-e2ee.md §4: the release rides on an accepted notice for this
        // exact session. A session still at `request` / `authorize`, or a
        // release naming some other Event as its notice, has no notice.
        if session.stage != AuditSessionStage::Notice
            || session.notice_ref.as_deref() != Some(payload.notice_ref.as_str())
        {
            return rejected(arkret_wire::ReasonCode::AUDIT_RELEASE_NOTICE_MISSING);
        }
        if session
            .approved_release_mode
            .is_some_and(|mode| mode != payload.release_mode)
        {
            return rejected(arkret_wire::ReasonCode::AUDIT_RELEASE_MANIFEST_INVALID);
        }

        if let Some(reason) = binding_manifest_violation(&binding, &payload) {
            return rejected(reason);
        }
        if let Some(reason) = release_attestation_violation(
            &binding,
            &payload,
            session.approved_recipient_audit_actor_id.as_deref(),
            operation.created_at,
        ) {
            return rejected(reason);
        }

        let Some(cell) = release_cell(&session_id) else {
            return rejected(arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED);
        };
        let Some(value) = self
            .projected_cell_writes()
            .iter()
            .find(|write| write.cell_id == cell)
            .and_then(|write| match &write.op {
                ProjectedOp::Direct(op) if op.op_type == LatticeOpType::Append => op.value.clone(),
                _ => None,
            })
        else {
            return rejected(arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED);
        };
        let mut log = match self.cells.get(&cell) {
            Some(CellState::Value(Value::Array(entries))) => entries.clone(),
            Some(CellState::Value(_)) | Some(CellState::Bottom(_)) => {
                return rejected(arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED);
            }
            None => Vec::new(),
        };
        log.push(value);
        self.cells.insert(cell, CellState::Value(Value::Array(log)));
        ProjectionEffect::AuditReleaseProjected {
            session_id,
            release_id: arkret_identifiers::AuditReleaseId::from_event_id(
                &operation.context.event_id,
            )
            .to_string(),
        }
    }
}

const fn audit_session_stage_str(stage: AuditSessionStage) -> &'static str {
    match stage {
        AuditSessionStage::Request => "request",
        AuditSessionStage::Authorize => "authorize",
        AuditSessionStage::Notice => "notice",
        AuditSessionStage::Close => "close",
    }
}

/// `audited-e2ee.md` §6 attestation verification, evaluated at `ak.audit.release`
/// admission.
///
/// The split between the two reason codes is the one the spec draws and is not
/// interchangeable: `_invalid` means the evidence itself is untrustworthy — its
/// chain root is not one the Realm declared, its window is closed or wider than
/// the profile allows, its platform or measurement is not one the binding
/// permits — while `_mismatch` means valid evidence that describes some other
/// Realm, service, policy revision or auditor than the one this release runs
/// under.
///
/// Freshness is judged against the Event's own signed `created_at`, never a
/// receiver clock, so every replay of this Event reaches the same verdict.
fn release_attestation_violation(
    binding: &Value,
    payload: &AuditReleasePayload,
    approved_recipient_audit_actor_id: Option<&str>,
    event_created_at: DateTime<Utc>,
) -> Option<&'static str> {
    let invalid = arkret_wire::ReasonCode::AUDIT_RELEASE_ATTESTATION_INVALID;
    let mismatch = arkret_wire::ReasonCode::AUDIT_RELEASE_ATTESTATION_MISMATCH;

    // The binding's assurance class decides whether evidence is required at
    // all. A `disclosed_policy` binding carrying evidence would be claiming a
    // guarantee it never bought, so the member is rejected rather than ignored.
    let attested = binding.get("audit_assurance_class").and_then(Value::as_str)
        == Some(ATTESTED_HARDWARE_ASSURANCE);
    let Some(attestation) = payload.release_attestation.as_ref() else {
        return attested.then_some(arkret_wire::ErrorCode::SCHEMA_VIOLATION);
    };
    if !attested {
        return Some(arkret_wire::ErrorCode::SCHEMA_VIOLATION);
    }
    let policy: AuditAttestationPolicy = match binding.get("attestation_policy") {
        Some(value) => match serde_json::from_value(value.clone()) {
            Ok(policy) => policy,
            Err(_) => return Some(invalid),
        },
        // An `attested_hardware` binding without a policy has no trust root
        // list, so there is nothing to validate the evidence against.
        None => return Some(invalid),
    };

    if !attestation.platform.family.is_hardware_backed() {
        return Some(invalid);
    }
    let Ok(root_digest) = attestation.chain_root_digest() else {
        return Some(invalid);
    };
    if !policy.trust_root_digests.contains(&root_digest) {
        return Some(invalid);
    }
    if !policy
        .allowed_code_digests
        .contains(&attestation.measurement.code_digest)
    {
        return Some(invalid);
    }
    if !policy
        .allowed_policy_versions
        .contains(&attestation.measurement.policy_version)
    {
        return Some(invalid);
    }
    let validity = &attestation.validity;
    if validity.expires_at <= validity.not_before
        || validity.expires_at - validity.not_before > AuditReleaseAttestation::MAX_VALIDITY
    {
        return Some(invalid);
    }
    if event_created_at < validity.not_before || event_created_at >= validity.expires_at {
        return Some(invalid);
    }

    if attestation.realm_id.as_str() != payload.realm_id.as_str() {
        return Some(mismatch);
    }
    if binding.get("service_id").and_then(Value::as_str) != Some(attestation.service_id.as_str()) {
        return Some(mismatch);
    }
    if binding
        .get("policy_version_digest")
        .and_then(Value::as_str)
        .is_some_and(|digest| digest != attestation.audit_policy_version_digest.as_str())
    {
        return Some(mismatch);
    }
    // The approved recipient is the auditor the authorize step named. Evidence
    // attesting a different actor's output path proves nothing about where this
    // release's material is going.
    if approved_recipient_audit_actor_id
        .is_some_and(|actor| actor != attestation.audit_actor_id.to_string())
    {
        return Some(mismatch);
    }
    None
}

/// The manifest rules the binding document itself decides. Every one of these
/// is `audited-e2ee.md` §3-§4 read off the active binding, except the
/// activation-frontier pair, which is what makes a release non-retroactive.
fn binding_manifest_violation(
    binding: &Value,
    payload: &AuditReleasePayload,
) -> Option<&'static str> {
    let manifest_invalid = arkret_wire::ReasonCode::AUDIT_RELEASE_MANIFEST_INVALID;
    let retroactive = arkret_wire::ReasonCode::AUDIT_RELEASE_RETROACTIVE_SCOPE_FORBIDDEN;

    if binding.get("applet_id").and_then(Value::as_str) != Some(payload.applet_id.as_str())
        || binding.get("service_id").and_then(Value::as_str) != Some(payload.service_id.as_str())
    {
        return Some(manifest_invalid);
    }
    if binding
        .get("policy_version_digest")
        .and_then(Value::as_str)
        .is_some_and(|digest| digest != payload.policy_version_digest.as_str())
    {
        return Some(manifest_invalid);
    }
    let release_mode = match serde_json::to_value(payload.release_mode) {
        Ok(value) => value,
        Err(_) => return Some(manifest_invalid),
    };
    if binding
        .get("allowed_release_modes")
        .and_then(Value::as_array)
        .is_some_and(|modes| !modes.contains(&release_mode))
    {
        return Some(manifest_invalid);
    }
    if binding
        .get("purpose_kinds")
        .and_then(Value::as_array)
        .is_some_and(|kinds| {
            !kinds
                .iter()
                .any(|kind| kind.as_str() == Some(payload.purpose_kind.as_str()))
        })
    {
        return Some(manifest_invalid);
    }

    // The eligibility proof is the release's own claim about where the audit
    // window opens. It has to be the binding's claim, or the release is
    // reaching behind the activation frontier under a proof of its own making.
    let first_auditable_epoch = binding.get("first_auditable_epoch").and_then(Value::as_u64);
    if first_auditable_epoch
        .is_some_and(|epoch| epoch != payload.eligibility_proof.first_auditable_epoch)
    {
        return Some(retroactive);
    }
    if binding
        .get("activation_frontier_digest")
        .and_then(Value::as_str)
        .is_some_and(|digest| {
            digest
                != payload
                    .eligibility_proof
                    .binding_activation_frontier_digest
                    .as_str()
        })
    {
        return Some(retroactive);
    }
    if let Some(range) = payload.sealed_epoch_range.as_ref() {
        if first_auditable_epoch.is_some_and(|epoch| range.first_epoch < epoch) {
            return Some(retroactive);
        }
        // audited-e2ee.md §1: epoch material may only leave a window the
        // Realm has already sealed, and the commit that sealed it is named.
        if payload.sealed_by_commit_ref.is_none() {
            return Some(manifest_invalid);
        }
    }
    None
}
