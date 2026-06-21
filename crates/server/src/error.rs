//! Soland error integration for canonical Cokret SDK error codes.
//!
//! Wire-form error codes are owned by `cokret_sdk::ErrorCode`; this module
//! only adds soland-specific Salvo rendering and typed endpoint plumbing.

/// Round C44 (2026-05-18; spec dc01ad7 Tier-0) — registered
/// `failed_precondition` reason codes new in this round. These are
/// re-exported from cokret-sdk so soland call sites can use
/// `crate::error::reasons::INCEPTION_UPGRADE_FINGERPRINT_MISMATCH` directly.
pub mod reasons {
    use cokret_sdk::error as core_error;

    // SEC-04 — receiver-side independent 24h inception-key online-window cap
    // (`identity/key-management.md` §5.0.1 step 5). Re-exported from cokret-sdk
    // so soland never inlines the wire literal.
    pub const INCEPTION_KEY_WINDOW_EXCEEDED: &str =
        core_error::REASON_INCEPTION_KEY_WINDOW_EXCEEDED;

    // S3 — `did:web` → `did:webvh` upgrade evidence.
    pub const INCEPTION_UPGRADE_FINGERPRINT_MISMATCH: &str =
        core_error::REASON_INCEPTION_UPGRADE_FINGERPRINT_MISMATCH;
    pub const INCEPTION_UPGRADE_SIGNATURE_CHAIN_INVALID: &str =
        core_error::REASON_INCEPTION_UPGRADE_SIGNATURE_CHAIN_INVALID;
    pub const INCEPTION_UPGRADE_OLD_DOCUMENT_HASH_MISMATCH: &str =
        core_error::REASON_INCEPTION_UPGRADE_OLD_DOCUMENT_HASH_MISMATCH;
    pub const INCEPTION_UPGRADE_EVIDENCE_INSUFFICIENT: &str =
        core_error::REASON_INCEPTION_UPGRADE_EVIDENCE_INSUFFICIENT;

    // S6 — `attested_hardware` Audit Agent removal pairing.
    pub const AUDIT_AGENT_KEY_DESTRUCTION_ATTESTATION_MISSING: &str =
        core_error::REASON_AUDIT_AGENT_KEY_DESTRUCTION_ATTESTATION_MISSING;
    pub const AUDIT_AGENT_REMOVE_REQUIRES_PAIRED_DESTRUCTION_ATTESTATION: &str =
        core_error::REASON_AUDIT_AGENT_REMOVE_REQUIRES_PAIRED_DESTRUCTION_ATTESTATION;
    pub const AUDIT_AGENT_DESTRUCTION_NOT_PAIRED_WITH_REMOVE: &str =
        core_error::REASON_AUDIT_AGENT_DESTRUCTION_NOT_PAIRED_WITH_REMOVE;
    pub const AUDIT_AGENT_DESTRUCTION_PROOF_NOT_ENCLAVE_SIGNED: &str =
        core_error::REASON_AUDIT_AGENT_DESTRUCTION_PROOF_NOT_ENCLAVE_SIGNED;
    pub const AUDIT_AGENT_EPOCH_RANGE_INCOMPLETE: &str =
        core_error::REASON_AUDIT_AGENT_EPOCH_RANGE_INCOMPLETE;
    pub const AUDIT_AGENT_ATTESTATION_MISMATCH: &str =
        core_error::REASON_AUDIT_AGENT_ATTESTATION_MISMATCH;

    // Profile interactions.
    pub const MLS_SEND_PAUSE_ADVISORY_REQUIRES_E2EE_RELAXED_PROFILE: &str =
        core_error::REASON_MLS_SEND_PAUSE_ADVISORY_REQUIRES_E2EE_RELAXED_PROFILE;
    pub const CONFLICTING_E2EE_PROFILES: &str = core_error::REASON_CONFLICTING_E2EE_PROFILES;
    pub const LITE_PROFILE_WRITES_DISALLOWED_EVENT_KIND: &str =
        core_error::REASON_LITE_PROFILE_WRITES_DISALLOWED_EVENT_KIND;

    // ── Round C45 (2026-05-18 main; spec 5ed365c) — lifecycle / patch /
    // nonce / accountability_grant / delegation / recovery / sender
    // commitment / range completeness / deprecation reason codes. Surfaced
    // by re-export so soland call sites can use the `reasons::` namespace.
    pub const STRAND_NOT_ACTIVE: &str = core_error::REASON_STRAND_NOT_ACTIVE;
    pub const STRAND_NOT_ARCHIVED: &str = core_error::REASON_STRAND_NOT_ARCHIVED;
    pub const STRAND_ALREADY_TERMINAL: &str = core_error::REASON_STRAND_ALREADY_TERMINAL;
    pub const SPACE_NOT_ACTIVE: &str = core_error::REASON_SPACE_NOT_ACTIVE;
    pub const SPACE_NOT_ARCHIVED: &str = core_error::REASON_SPACE_NOT_ARCHIVED;
    pub const SPACE_ALREADY_TERMINAL: &str = core_error::REASON_SPACE_ALREADY_TERMINAL;
    pub const SPACE_PARENT_CYCLE: &str = core_error::REASON_SPACE_PARENT_CYCLE;
    pub const SPACE_HAS_LIVE_DEPENDENTS: &str = core_error::REASON_SPACE_HAS_LIVE_DEPENDENTS;
    pub const MORPH_NOT_ACTIVE: &str = core_error::REASON_MORPH_NOT_ACTIVE;
    pub const MORPH_NOT_ARCHIVED: &str = core_error::REASON_MORPH_NOT_ARCHIVED;
    pub const MORPH_ALREADY_TERMINAL: &str = core_error::REASON_MORPH_ALREADY_TERMINAL;
    pub const MESSAGE_ALREADY_TERMINAL: &str = core_error::REASON_MESSAGE_ALREADY_TERMINAL;
    pub const RELATION_ALREADY_TERMINAL: &str = core_error::REASON_RELATION_ALREADY_TERMINAL;

    pub const HATE_SPEECH: &str = core_error::REASON_HATE_SPEECH;
    pub const NSFW: &str = core_error::REASON_NSFW;
    pub const ILLEGAL: &str = core_error::REASON_ILLEGAL;
    pub const MISINFORMATION: &str = core_error::REASON_MISINFORMATION;
    pub const OTHER: &str = core_error::REASON_OTHER;

    pub const CURSOR_INTEGRITY_INVALID: &str = core_error::REASON_CURSOR_INTEGRITY_INVALID;
    pub const CLAIM_RATE_LIMITED: &str = core_error::REASON_CLAIM_RATE_LIMITED;
    pub const NAMING_CONVENTION_VIOLATION: &str = core_error::REASON_NAMING_CONVENTION_VIOLATION;
    pub const APPROVAL_NONCE_REUSED: &str = core_error::REASON_APPROVAL_NONCE_REUSED;
    pub const EXECUTED_BY_MISSING: &str = core_error::REASON_EXECUTED_BY_MISSING;
    pub const THIRD_PARTY_INVITE_TOKEN_IN_QUERY: &str =
        core_error::REASON_THIRD_PARTY_INVITE_TOKEN_IN_QUERY;

    pub const PATCH_PATH_INVALID: &str = core_error::REASON_PATCH_PATH_INVALID;
    pub const PATCH_PATH_REDUCER_MANAGED: &str = core_error::REASON_PATCH_PATH_REDUCER_MANAGED;
    pub const PATCH_UNSET_REDACTABLE_FIELD: &str = core_error::REASON_PATCH_UNSET_REDACTABLE_FIELD;
    pub const PATCH_SELECTOR_NO_MATCH: &str = core_error::REASON_PATCH_SELECTOR_NO_MATCH;
    pub const PATCH_SELECTOR_AMBIGUOUS: &str = core_error::REASON_PATCH_SELECTOR_AMBIGUOUS;

    pub const AEAD_NONCE_COUNTER_REPLAY: &str = core_error::REASON_AEAD_NONCE_COUNTER_REPLAY;
    pub const AEAD_NONCE_DERIVATION_INVALID: &str =
        core_error::REASON_AEAD_NONCE_DERIVATION_INVALID;

    pub const ACCOUNTABILITY_GRANT_MISSING: &str = core_error::REASON_ACCOUNTABILITY_GRANT_MISSING;
    pub const KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH: &str =
        core_error::REASON_KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH;

    pub const DELEGATION_CYCLE: &str = core_error::REASON_DELEGATION_CYCLE;
    pub const DELEGATION_EXPIRY_WIDENING: &str = core_error::REASON_DELEGATION_EXPIRY_WIDENING;

    pub const RECOVERY_WITNESS_MISSING: &str = core_error::REASON_RECOVERY_WITNESS_MISSING;
    pub const RECOVERY_WITNESS_INVALID: &str = core_error::REASON_RECOVERY_WITNESS_INVALID;
    pub const RECOVERY_WITNESS_POST_CONFLICT: &str =
        core_error::REASON_RECOVERY_WITNESS_POST_CONFLICT;
    pub const RECOVERY_CAPABILITY_NOT_SEALED: &str =
        core_error::REASON_RECOVERY_CAPABILITY_NOT_SEALED;

    pub const CHALLENGE_PROOF_INVALID: &str = core_error::REASON_CHALLENGE_PROOF_INVALID;
    pub const INVALID_TASK_FSM_TRANSITION: &str = core_error::REASON_INVALID_TASK_FSM_TRANSITION;

    // `mixed_secret_storage_disallowed_by_profile` was dropped from the
    // spec registry in round C47 (spec e10b6ad); soland no longer surfaces
    // a dedicated reason for that check — schema validation in the key
    // management decode path now rejects mixed storage as
    // `schema_violation`.

    pub const AUDIT_CAPABILITY_INCOMPLETE: &str = core_error::REASON_AUDIT_CAPABILITY_INCOMPLETE;
    pub const WATCH_MUST_BE_SELF: &str = core_error::REASON_WATCH_MUST_BE_SELF;
    pub const WATCH_MUTED_MUST_BE_SELF: &str = core_error::REASON_WATCH_MUTED_MUST_BE_SELF;
    pub const WATCH_LEVEL_PUBLIC_MUST_BE_SELF: &str =
        core_error::REASON_WATCH_LEVEL_PUBLIC_MUST_BE_SELF;
    pub const MANAGE_OTHERS_AUDIT_MISSING: &str = core_error::REASON_MANAGE_OTHERS_AUDIT_MISSING;
    pub const CROSS_SPACE_STRUCTURAL_RELATION: &str =
        core_error::REASON_CROSS_SPACE_STRUCTURAL_RELATION;
    pub const JOIN_AUTHORISATION_INVALID: &str = core_error::REASON_JOIN_AUTHORISATION_INVALID;
    pub const JOIN_RULE_POLICY_MISMATCH: &str = core_error::REASON_JOIN_RULE_POLICY_MISMATCH;
    pub const CROSS_SIGNING_RESET: &str = core_error::REASON_CROSS_SIGNING_RESET;
    pub const TTL_EXPIRED: &str = core_error::REASON_TTL_EXPIRED;
    pub const NOT_PROVISIONED: &str = core_error::REASON_NOT_PROVISIONED;

    pub const MORPH_SCHEMA_REFS_EVOLUTION_UNAUTHORIZED: &str =
        core_error::REASON_MORPH_SCHEMA_REFS_EVOLUTION_UNAUTHORIZED;
    pub const MORPH_SCHEMA_REFS_TRANSFORMATION_UNSUPPORTED: &str =
        core_error::REASON_MORPH_SCHEMA_REFS_TRANSFORMATION_UNSUPPORTED;
    pub const MORPH_SCHEMA_VERSION_BINDING_MISSING: &str =
        core_error::REASON_MORPH_SCHEMA_VERSION_BINDING_MISSING;

    pub const RANGE_COMPLETENESS_ROOT_MISMATCH: &str =
        core_error::REASON_RANGE_COMPLETENESS_ROOT_MISMATCH;
    pub const RANGE_COMPLETENESS_ACTOR_SEQ_GAP: &str =
        core_error::REASON_RANGE_COMPLETENESS_ACTOR_SEQ_GAP;

    // ── CKP-0007 (spec b7d35be / floor 2b0d70d) — Circle reason codes.
    //
    // The six new sub-reasons registered against `failed_precondition`
    // / `schema_violation` for the Circle invariants in
    // `zh/models/circle.md`. The sixth top-level Circle code is the
    // existing `delivery_binding_handed_over`, which is already
    // surfaced via the round-4 ErrorCode variant.
    pub const CIRCLE_REALM_MISMATCH: &str = core_error::REASON_CIRCLE_REALM_MISMATCH;
    pub const CIRCLE_NOT_ACTIVE: &str = core_error::REASON_CIRCLE_NOT_ACTIVE;
    pub const CIRCLE_MEMBER_MUST_BE_REALM_MEMBER: &str =
        core_error::REASON_CIRCLE_MEMBER_MUST_BE_REALM_MEMBER;
    pub const CIRCLE_ENCRYPTION_BELOW_REALM_FLOOR: &str =
        core_error::REASON_CIRCLE_ENCRYPTION_BELOW_REALM_FLOOR;
    pub const CONTENT_ENCRYPTION_FLOOR_VIOLATION: &str =
        core_error::REASON_CONTENT_ENCRYPTION_FLOOR_VIOLATION;
    pub const SCOPE_REBIND_FORBIDDEN: &str = core_error::REASON_SCOPE_REBIND_FORBIDDEN;
    pub const METADATA_ENCRYPTION_FLOOR_VIOLATION: &str =
        core_error::REASON_METADATA_ENCRYPTION_FLOOR_VIOLATION;

    // ── Reaction model (spec strand-and-message.md §9.8, commit 4d9438f) —
    // v1 Reaction target-scope sub-reasons. `reaction_target_unsupported`
    // sits under `schema_violation`; `reaction_scope_mismatch` under
    // `failed_precondition`.
    pub const REACTION_TARGET_UNSUPPORTED: &str = core_error::REASON_REACTION_TARGET_UNSUPPORTED;
    pub const REACTION_SCOPE_MISMATCH: &str = core_error::REASON_REACTION_SCOPE_MISMATCH;
    pub const CONTACT_NOT_ACCEPTED: &str = core_error::REASON_CONTACT_NOT_ACCEPTED;
    pub const CONTACT_CONSENT_MISSING: &str = core_error::REASON_CONTACT_CONSENT_MISSING;

    /// CKP-0007 reason codes registered in this round. Test scaffolding
    /// uses this slice to assert the full set is surfaced through
    /// `crate::error::reasons`.
    pub const CKP_0007: &[&str] = &[
        CIRCLE_REALM_MISMATCH,
        CIRCLE_NOT_ACTIVE,
        CIRCLE_MEMBER_MUST_BE_REALM_MEMBER,
        CIRCLE_ENCRYPTION_BELOW_REALM_FLOOR,
        CONTENT_ENCRYPTION_FLOOR_VIOLATION,
        SCOPE_REBIND_FORBIDDEN,
        METADATA_ENCRYPTION_FLOOR_VIOLATION,
    ];

    // Agent / pairing / session-grant reason codes.
    pub const PROOF_INVALID: &str = "proof_invalid";
    pub const ACTOR_KIND_REDUCER_MANAGED: &str = "actor_kind_reducer_managed";
    pub const EFFECTIVE_SCOPE_REDUCER_MANAGED: &str =
        core_error::REASON_EFFECTIVE_SCOPE_REDUCER_MANAGED;

    // Media binding reason codes.
    pub const UNKNOWN_FOCUS_TYPE: &str = "unknown_focus_type";
    pub const FOCUS_MISMATCH: &str = "focus_mismatch";
    pub const TOKEN_ISSUER_UNAUTHORISED: &str = core_error::REASON_TOKEN_ISSUER_UNAUTHORISED;
    pub const PARTICIPANT_BINDING_INVALID: &str = "participant_binding_invalid";
    pub const PARTICIPANT_IDENTITY_UNRECOGNISED: &str = "participant_identity_unrecognised";
    pub const SESSION_FOCUS_ALREADY_COMMITTED: &str = "session_focus_already_committed";
    pub const E2EE_KEY_SOURCE_UNAUTHORISED: &str = core_error::REASON_E2EE_KEY_SOURCE_UNAUTHORISED;
    pub const FOCUS_UNAVAILABLE_FOR_CLIENT: &str = "focus_unavailable_for_client";

    // Call moderation reason codes (webrtc-signaling.md §3a).
    pub const CALL_MODERATION_UNAUTHORISED: &str = "call_moderation_unauthorised";
    pub const CALL_PARTICIPANT_REMOVED: &str = "call_participant_removed";

    // Call capability gating reason codes (webrtc-signaling.md §3 / §8).
    pub const MEDIA_PERMISSION_DENIED: &str = core_error::ERROR_CODE_MEDIA_PERMISSION_DENIED;
    pub const RECORDING_DENIED: &str = core_error::ERROR_CODE_RECORDING_DENIED;

    // Call recording / transcription lifecycle reason codes
    // (call-state.md §5 / §5.1 / §5.2 / §7).
    pub const RECORDING_CONSENT_REQUIRED: &str = core_error::REASON_RECORDING_CONSENT_REQUIRED;
    pub const TRANSCRIPTION_DENIED: &str = "transcription_denied";
    pub const TRANSCRIPTION_ARTIFACT_PIPELINE_BYPASSED: &str =
        "transcription_artifact_pipeline_bypassed";
    pub const CALL_SUMMARY_INVALID: &str = "call_summary_invalid";
    pub const LEGAL_HOLD_ACTIVE: &str = core_error::REASON_LEGAL_HOLD_ACTIVE;

    // Recovery reason codes.
    pub const RECOVERY_WITNESS_REVOKE_LAGGING: &str = "recovery_witness_revoke_lagging";

    // MemberIdentity append-only replacement event reason codes.
    pub const MEMBER_IDENTITY_UNKNOWN_SEGMENT: &str = "member_identity_unknown_segment";

    // Federation / admission reason codes that are not top-level SDK variants.
    pub const CROSS_DOMAIN_REPLAY_REJECTED: &str = "cross_domain_replay_rejected";
    pub const RESET_EVENT_ID_MISMATCH: &str = "reset_event_id_mismatch";
    pub const E2EE_RELAXED_DISALLOWED_IN_COMPLIANCE_PROFILE: &str =
        "e2ee_relaxed_disallowed_in_compliance_profile";
    pub const MEDIA_PLAINTEXT_SERVICE_NOT_AUTHORISED: &str =
        "media_plaintext_service_not_authorised";
    pub const BLOB_REDACTED: &str = "blob_redacted";

    // MemberIdentity / handle-claim wire-shape reason codes.
    pub const MEMBER_IDENTITY_HANDLE_FIELD_FORBIDDEN: &str =
        "member_identity_handle_field_forbidden";
    pub const CLAIM_TYPE_UNSUPPORTED: &str = "claim_type_unsupported";
    pub const HANDLE_CLAIM_SUBJECT_NOT_PRINCIPAL_DID: &str =
        "handle_claim_subject_not_principal_did";
}
use salvo::async_trait;
use salvo::http::StatusCode;
use salvo::oapi::{self, Components, EndpointOutRegister, Operation, ToSchema};
use salvo::prelude::*;

use crate::routing::system::util::render_error;

/// Construct an [`AppError`] with a canonical [`ErrorCode`] variant.
///
/// Two forms:
///
/// ```ignore
/// // Plain (or captured-interpolation) message:
/// return Err(app_error!(InvalidParam, "bad space_id"));
/// return Err(app_error!(InvalidParam, "invalid space_id: {err}"));
///
/// // Explicit-args `format!` variant:
/// return Err(app_error!(InvalidParam, "invalid space_id: {}", err));
/// ```
///
/// The first argument is a bare variant identifier resolved against
/// [`crate::error::ErrorCode`] (i.e. `InvalidParam`, not
/// `ErrorCode::InvalidParam`). When the message argument is a string
/// literal it is forwarded through `format!` so captured-arg
/// interpolation (`{var}`) works in the single-arg form as well.
/// Non-literal `String`/`&str` expressions are passed through unchanged.
///
/// This replaces the boilerplate
/// `AppError::new(ErrorCode::X, format!("...", ...))` pattern that
/// otherwise litters every handler module. Prefer the macro over
/// `AppError::new(...)` in new code.
#[macro_export]
macro_rules! app_error {
    ($code:ident, $fmt:literal $(, $($arg:tt)*)?) => {
        $crate::error::AppError::new(
            $crate::error::ErrorCode::$code,
            format!($fmt $(, $($arg)*)?),
        )
    };
    ($code:ident, $msg:expr $(,)?) => {
        $crate::error::AppError::new($crate::error::ErrorCode::$code, $msg)
    };
}

pub use cokret_sdk::ErrorCode;

/// Convert the SDK registry status into Salvo's `StatusCode`.
pub fn error_http_status(code: ErrorCode) -> StatusCode {
    StatusCode::from_u16(code.http_status()).expect("registry status codes are valid HTTP statuses")
}

/// Render an SDK-owned error code through soland's standard error envelope.
pub fn render_error_code(code: ErrorCode, res: &mut Response, message: &str) {
    render_error(res, error_http_status(code), code.as_str(), message);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sdk_error_codes_are_soland_source_of_truth() {
        assert_eq!(
            ErrorCode::ALL.len(),
            cokret_sdk::error::KNOWN_ERROR_CODES.len(),
            "soland must use the SDK registry shape directly",
        );
        assert_eq!(ErrorCode::from_wire("bad_json"), Some(ErrorCode::BadJson));
        assert_eq!(
            ErrorCode::from_wire("directory_not_authorized"),
            Some(ErrorCode::DirectoryNotAuthorized),
        );
        assert_eq!(
            error_http_status(ErrorCode::BadJson),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            error_http_status(ErrorCode::DirectoryNotAuthorized),
            StatusCode::FORBIDDEN,
        );
    }
}

// ── AppError + typed-endpoint integration ────────────────────────────────
//
// `AppError` is the typed error returned by `#[endpoint]` handlers. It carries
// a canonical [`ErrorCode`] (registry-locked), a human-readable message, and
// an optional HTTP status override. Both `Writer` and `EndpointOutRegister`
// are implemented so the same value drives both runtime rendering and
// OpenAPI doc generation.

/// Typed error returned by `#[endpoint]` handlers.
#[derive(Debug, Clone)]
pub struct AppError {
    pub code: ErrorCode,
    pub message: String,
    /// When set, overrides the registry-derived HTTP status. Most call sites
    /// should leave this `None` and let the registry decide; lifecycle paths
    /// (`401` on missing token vs `403` on capability denial) sometimes need
    /// the override.
    pub status: Option<StatusCode>,
    /// When set, overrides the wire-form `error.code` string. Use sparingly -
    /// only for handlers that emit a non-canonical code downstream
    /// clients (or tests) depend on (e.g. `unknown_schema`,
    /// `<kind>_not_active`, `batch_not_supported`). New code should prefer
    /// a canonical `ErrorCode` variant.
    pub wire_code_override: Option<String>,
    /// Free-form diagnostic explaining *why* this error fired.
    ///
    /// Round 2 — surfaced through the rendered envelope as
    /// `error.details.reason_detail` so on-call has something more
    /// specific than the canonical `code` to grep for. The shape is
    /// intentionally `Option<String>` (no enum, no schema) because the
    /// string is unstable across releases — see the [`EndpointOutRegister`]
    /// doc on the response: clients MUST NOT parse this value, only
    /// log/display it.
    pub reason_detail: Option<String>,
    /// When set, render a top-level `reason` field on the error envelope.
    ///
    /// Unlike [`Self::reason_detail`] (an opaque diagnostic at
    /// `error.details.reason_detail`), this is a **stable, normative**
    /// discriminator that the wire contract pins independently of the generic
    /// `error.code`. COT-03-001 / `applet-integration.md` §7.3.1 uses it for the
    /// inbound transaction-push signature failure codes
    /// (`http_signature_required` / `http_signature_invalid` /
    /// `signature_window_invalid`), where `error.code` stays the generic
    /// `unauthenticated` and the discriminator travels in `reason`.
    pub top_level_reason: Option<String>,
}

impl AppError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            status: None,
            wire_code_override: None,
            reason_detail: None,
            top_level_reason: None,
        }
    }

    pub fn with_status(mut self, status: StatusCode) -> Self {
        self.status = Some(status);
        self
    }

    /// Override the on-wire `error.code` string. See `wire_code_override` for
    /// the rationale + caveats.
    pub fn with_wire_code(mut self, wire_code: impl Into<String>) -> Self {
        self.wire_code_override = Some(wire_code.into());
        self
    }

    /// Attach a free-form diagnostic. See [`AppError::reason_detail`].
    ///
    /// The value is rendered into the wire envelope at
    /// `error.details.reason_detail` and the OpenAPI schema annotates
    /// it as unstable / opaque.
    pub fn with_reason_detail(mut self, reason_detail: impl Into<String>) -> Self {
        self.reason_detail = Some(reason_detail.into());
        self
    }

    /// Attach a stable, normative top-level `reason` discriminator. See
    /// [`AppError::top_level_reason`]. Used by the COT-03-001 inbound
    /// transaction-push signature path so the `reason` carries the §7.3.1
    /// failure code while `error.code` stays generic.
    pub fn with_top_level_reason(mut self, reason: impl Into<String>) -> Self {
        self.top_level_reason = Some(reason.into());
        self
    }

    /// Resolve the HTTP status to use when rendering this error: explicit
    /// override first, then the registry binding.
    pub fn http_status(&self) -> StatusCode {
        self.status.unwrap_or_else(|| error_http_status(self.code))
    }

    /// Resolve the on-wire `error.code` string: explicit override first, then the
    /// canonical mapping from the registry.
    pub fn wire_code(&self) -> &str {
        self.wire_code_override
            .as_deref()
            .unwrap_or_else(|| self.code.as_str())
    }

    // ── Convenience constructors for the most-used codes. The full
    // `ErrorCode` set is always available via `AppError::new(code, msg)`.

    pub fn bad_json(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::BadJson, message)
    }
    pub fn missing_param(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::MissingParam, message)
    }
    pub fn invalid_param(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidParam, message)
    }
    pub fn unauthenticated(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Unauthenticated, message)
    }
    pub fn capability_denied(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::CapabilityDenied, message)
    }
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, message)
    }
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Conflict, message)
    }
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InternalError, message)
    }
    pub fn unsupported_feature(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::UnsupportedFeature, message)
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for AppError {}

impl From<ErrorCode> for AppError {
    fn from(code: ErrorCode) -> Self {
        Self::new(code, "")
    }
}

#[async_trait]
impl Writer for AppError {
    async fn write(self, _req: &mut Request, depot: &mut Depot, res: &mut Response) {
        let status = self.http_status();
        let wire = self.wire_code().to_owned();
        let development_mode = depot
            .obtain::<crate::state::AppState>()
            .map(|state| state.config.development_mode)
            .unwrap_or(false);
        let redact_internal = self.code == ErrorCode::InternalError && !development_mode;
        if redact_internal {
            tracing::error!(
                status = status.as_u16(),
                wire_code = %wire,
                internal_message = %self.message,
                "internal error response redacted"
            );
        }
        let public_message = if redact_internal {
            "internal error"
        } else {
            self.message.as_str()
        };
        if let Some(reason) = self.top_level_reason.as_deref() {
            crate::routing::system::util::render_error_with_top_level_reason(
                res,
                status,
                &wire,
                public_message,
                reason,
                self.reason_detail.as_deref(),
            );
        } else if let Some(reason_detail) = self.reason_detail.as_deref() {
            crate::routing::system::util::render_error_with_detail(
                res,
                status,
                &wire,
                public_message,
                reason_detail,
            );
        } else {
            render_error(res, status, &wire, public_message);
        }
    }
}

impl EndpointOutRegister for AppError {
    fn register(components: &mut Components, operation: &mut Operation) {
        // Reuse `cokret_sdk::ErrorEnvelope` (already `ToSchema` under the
        // SDK's `salvo` feature) as the response body schema for every error
        // status. The wire representation is the spec-canonical
        // `{ ok: false, error: { code, message, ... }, request_id }`.
        //
        // Round 2 — when an `AppError::reason_detail` is set, the
        // rendered envelope carries `error.details.reason_detail: string`.
        // The SDK schema already types `details` as `serde_json::Value`,
        // so the field is documentation-only — describe its shape and
        // stability contract in each response's `description` rather
        // than mutating the SDK-owned schema.
        let envelope_schema = <cokret_sdk::ErrorEnvelope as ToSchema>::to_schema(components);
        const REASON_DETAIL_DOC: &str = " (envelope `error.details.reason_detail`: \
            Option<String> — free-form diagnostic; unstable, do not parse)";
        let response = |description: &'static str| -> oapi::Response {
            let combined = format!("{description}{REASON_DETAIL_DOC}");
            oapi::Response::new(combined).add_content(
                "application/json",
                oapi::Content::new(envelope_schema.clone()),
            )
        };

        operation.responses.insert("400", response("Bad request"));
        operation
            .responses
            .insert("401", response("Unauthenticated"));
        operation
            .responses
            .insert("403", response("Capability denied"));
        operation.responses.insert("404", response("Not found"));
        operation.responses.insert("409", response("Conflict"));
        operation.responses.insert("429", response("Rate limited"));
        operation
            .responses
            .insert("500", response("Internal server error"));
    }
}
