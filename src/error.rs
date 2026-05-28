//! Soland error integration for canonical Contrix SDK error codes.
//!
//! Wire-form error codes are owned by `contrix_sdk::ErrorCode`; this module
//! only adds soland-specific Salvo rendering and typed endpoint plumbing.

/// Round C44 (2026-05-18; spec dc01ad7 Tier-0) — registered
/// `failed_precondition` reason codes new in this round. These are
/// re-exported from contrix-sdk so soland call sites can use
/// `crate::error::reasons::INCEPTION_UPGRADE_FINGERPRINT_MISMATCH` directly.
pub mod reasons {
    use contrix_sdk::error as core_error;

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
    pub const FLOW_NOT_ACTIVE: &str = core_error::REASON_FLOW_NOT_ACTIVE;
    pub const FLOW_NOT_ARCHIVED: &str = core_error::REASON_FLOW_NOT_ARCHIVED;
    pub const FLOW_ALREADY_TERMINAL: &str = core_error::REASON_FLOW_ALREADY_TERMINAL;
    pub const PLACE_NOT_ACTIVE: &str = core_error::REASON_PLACE_NOT_ACTIVE;
    pub const PLACE_NOT_ARCHIVED: &str = core_error::REASON_PLACE_NOT_ARCHIVED;
    pub const PLACE_ALREADY_TERMINAL: &str = core_error::REASON_PLACE_ALREADY_TERMINAL;
    pub const PLACE_PARENT_CYCLE: &str = core_error::REASON_PLACE_PARENT_CYCLE;
    pub const PLACE_HAS_LIVE_DEPENDENTS: &str = core_error::REASON_PLACE_HAS_LIVE_DEPENDENTS;
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
    pub const RECOVERY_CAPABILITY_NOT_ANCHORED: &str =
        core_error::REASON_RECOVERY_CAPABILITY_NOT_ANCHORED;

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

    pub const SENDER_COMMITMENT_INVALID: &str = core_error::REASON_SENDER_COMMITMENT_INVALID;
    pub const SENDER_COMMITMENT_MISSING: &str = core_error::REASON_SENDER_COMMITMENT_MISSING;
    pub const SENDER_COMMITMENT_SEQ_REPLAY: &str = core_error::REASON_SENDER_COMMITMENT_SEQ_REPLAY;
    pub const SENDER_COMMITMENT_CIPHERTEXT_MISMATCH: &str =
        core_error::REASON_SENDER_COMMITMENT_CIPHERTEXT_MISMATCH;
    pub const SENDER_COMMITMENT_EPOCH_MISMATCH: &str =
        core_error::REASON_SENDER_COMMITMENT_EPOCH_MISMATCH;

    pub const RANGE_COMPLETENESS_ROOT_MISMATCH: &str =
        core_error::REASON_RANGE_COMPLETENESS_ROOT_MISMATCH;
    pub const RANGE_COMPLETENESS_ACTOR_SEQ_GAP: &str =
        core_error::REASON_RANGE_COMPLETENESS_ACTOR_SEQ_GAP;

    // ── CXP-0007 (spec b7d35be / floor 2b0d70d) — Circle reason codes.
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
    pub const SCOPE_REBIND_FORBIDDEN: &str = core_error::REASON_SCOPE_REBIND_FORBIDDEN;
    pub const METADATA_ENCRYPTION_FLOOR_VIOLATION: &str =
        core_error::REASON_METADATA_ENCRYPTION_FLOOR_VIOLATION;

    /// CXP-0007 reason codes registered in this round. Test scaffolding
    /// uses this slice to assert the full set is surfaced through
    /// `crate::error::reasons`.
    pub const CXP_0007: &[&str] = &[
        CIRCLE_REALM_MISMATCH,
        CIRCLE_NOT_ACTIVE,
        CIRCLE_MEMBER_MUST_BE_REALM_MEMBER,
        SCOPE_REBIND_FORBIDDEN,
        METADATA_ENCRYPTION_FLOOR_VIOLATION,
    ];

    // ── R3 (spec b47ff6ec, _before_todos.md §0.7) — Agent / pairing /
    // session-grant + media-binding (CXP-0010) + recovery / handle reason
    // codes. Exposed here so future R3.1 handler work can reference them
    // through the `crate::error::reasons` namespace without depending on
    // a parallel SDK PR landing first. Once contrix-rust-sdk adopts the
    // canonical `REASON_*` constants, swap these `pub const` literals for
    // re-exports the same way the C44/C45 block above does.
    //
    // TODO(R3.1): swap to `core_error::REASON_*` re-exports once SDK
    // ships the matching registry entries.

    // Agent / pairing / session-grant (8 codes).
    pub const PAIRING_REQUEST_EXPIRED: &str = "pairing_request_expired";
    pub const PROOF_INVALID: &str = "proof_invalid";
    pub const VERIFICATION_METHOD_PRINCIPAL_MISMATCH: &str =
        "verification_method_principal_mismatch";
    pub const AGENT_PAUSED: &str = "agent_paused";
    pub const AGENT_DEACTIVATED: &str = "agent_deactivated";
    pub const APPROVAL_ALREADY_CONSUMED: &str = "approval_already_consumed";
    pub const SIDECAR_CREATE_DENIED: &str = "sidecar_create_denied";
    pub const ACTOR_KIND_REDUCER_MANAGED: &str = "actor_kind_reducer_managed";

    // Media binding / CXP-0010 (10 codes).
    pub const FOCUS_MISMATCH: &str = "focus_mismatch";
    pub const UNKNOWN_FOCUS_TYPE: &str = "unknown_focus_type";
    pub const TOKEN_ISSUER_UNAUTHORISED: &str = "token_issuer_unauthorised";
    pub const PARTICIPANT_BINDING_INVALID: &str = "participant_binding_invalid";
    pub const PARTICIPANT_IDENTITY_UNRECOGNISED: &str = "participant_identity_unrecognised";
    pub const SESSION_FOCUS_ALREADY_COMMITTED: &str = "session_focus_already_committed";
    pub const E2EE_KEY_SOURCE_UNAUTHORISED: &str = "e2ee_key_source_unauthorised";
    pub const RECORDING_ARTIFACT_PIPELINE_BYPASSED: &str = "recording_artifact_pipeline_bypassed";
    pub const LEGACY_SINGLE_ENDPOINT_MEDIA_SERVICE: &str = "legacy_single_endpoint_media_service";
    pub const FOCUS_UNAVAILABLE_FOR_CLIENT: &str = "focus_unavailable_for_client";

    // Recovery / handle (2 codes).
    pub const RECOVERY_WITNESS_REVOKE_LAGGING: &str = "recovery_witness_revoke_lagging";
    pub const HANDLE_HOMOGRAPH_FORBIDDEN: &str = "handle_homograph_forbidden";

    // ── R3.1 (2026-05-27, contrix-spec @ 7157ee8) — MemberIdentity append-
    // only replacement event error codes. Re-exported from the SDK's
    // `ERROR_CODE_MEMBER_IDENTITY_*` constants so soland callsites have a
    // stable namespace match for the spec wire codes.
    pub const MEMBER_IDENTITY_STATE_MISMATCH: &str =
        core_error::ERROR_CODE_MEMBER_IDENTITY_STATE_MISMATCH;
    pub const MEMBER_IDENTITY_PROOF_INVALID: &str =
        core_error::ERROR_CODE_MEMBER_IDENTITY_PROOF_INVALID;
    pub const MEMBER_IDENTITY_REPLACEMENT_DIGEST_MISMATCH: &str =
        core_error::ERROR_CODE_MEMBER_IDENTITY_REPLACEMENT_DIGEST_MISMATCH;
    pub const MEMBER_IDENTITY_UNKNOWN_SEGMENT: &str =
        core_error::ERROR_CODE_MEMBER_IDENTITY_UNKNOWN_SEGMENT;

    /// R3.1 reason codes for the MemberIdentity append-only replacement
    /// event. Tests use this slice to assert the full set is surfaced.
    pub const R3_1_MEMBER_IDENTITY_REASONS: &[&str] = &[
        MEMBER_IDENTITY_STATE_MISMATCH,
        MEMBER_IDENTITY_PROOF_INVALID,
        MEMBER_IDENTITY_REPLACEMENT_DIGEST_MISMATCH,
        MEMBER_IDENTITY_UNKNOWN_SEGMENT,
    ];

    // ── R3.2 (2026-05-28, contrix-spec @ b56cab1) — wire-breaking
    // member-identity / handle-claim / mention reason codes. Defined as
    // soland-local `pub const` literals (canonical wire form) until the SDK
    // ships the matching `REASON_*` registry entries; once it does, swap to
    // `core_error::REASON_*` re-exports the same way the C44/C45 block does.
    // TODO(R3.2.1): swap to SDK re-exports once the registry lands.

    /// MIU-SOL-1 — `cx.member.identity.update` payload carried a forbidden
    /// handle field (`primary_handle` / `handles[]` / `verified_handle`).
    /// MemberIdentity no longer carries handle lifecycle; it lives solely on
    /// `cx.schema.handle_claim.v1`.
    pub const MEMBER_IDENTITY_HANDLE_FIELD_FORBIDDEN: &str =
        "member_identity_handle_field_forbidden";
    /// HC-SOL-1 — handle claim used the removed `claim_type=service_handle`.
    pub const CLAIM_TYPE_UNSUPPORTED: &str = "claim_type_unsupported";
    /// HC-SOL-2 — handle claim `subject` was not a holder/principal DID
    /// (e.g. `cx:actor:` / `cx:account:` / non-DID).
    pub const HANDLE_CLAIM_SUBJECT_NOT_PRINCIPAL_DID: &str =
        "handle_claim_subject_not_principal_did";
    /// HC-SOL-3 — a mention reference carried the legacy pre-R3.2 shape
    /// (`subject` / `handle` / `display_snapshot`) instead of the v2 shape
    /// (`subject_id` authoritative + audit metadata).
    pub const MENTION_REFERENCE_LEGACY_SHAPE: &str = "mention_reference_legacy_shape";

    /// R3.2 reason codes registered in this round. Test scaffolding uses
    /// this slice to assert the full set is surfaced through
    /// `crate::error::reasons`.
    pub const R3_2_REASONS: &[&str] = &[
        MEMBER_IDENTITY_HANDLE_FIELD_FORBIDDEN,
        CLAIM_TYPE_UNSUPPORTED,
        HANDLE_CLAIM_SUBJECT_NOT_PRINCIPAL_DID,
        MENTION_REFERENCE_LEGACY_SHAPE,
    ];

    /// R3 reason codes registered in this round. Test scaffolding uses this
    /// slice to assert the full set is surfaced through
    /// `crate::error::reasons`.
    pub const R3_NEW_REASONS: &[&str] = &[
        PAIRING_REQUEST_EXPIRED,
        PROOF_INVALID,
        VERIFICATION_METHOD_PRINCIPAL_MISMATCH,
        AGENT_PAUSED,
        AGENT_DEACTIVATED,
        APPROVAL_ALREADY_CONSUMED,
        SIDECAR_CREATE_DENIED,
        ACTOR_KIND_REDUCER_MANAGED,
        FOCUS_MISMATCH,
        UNKNOWN_FOCUS_TYPE,
        TOKEN_ISSUER_UNAUTHORISED,
        PARTICIPANT_BINDING_INVALID,
        PARTICIPANT_IDENTITY_UNRECOGNISED,
        SESSION_FOCUS_ALREADY_COMMITTED,
        E2EE_KEY_SOURCE_UNAUTHORISED,
        RECORDING_ARTIFACT_PIPELINE_BYPASSED,
        LEGACY_SINGLE_ENDPOINT_MEDIA_SERVICE,
        FOCUS_UNAVAILABLE_FOR_CLIENT,
        RECOVERY_WITNESS_REVOKE_LAGGING,
        HANDLE_HOMOGRAPH_FORBIDDEN,
    ];

    /// ERR-1 — per-handler reason-code wiring index.
    ///
    /// Each tuple `(reason, handler_site)` documents the canonical handler
    /// site responsible for emitting the corresponding R3 reason code.
    /// Test scaffolding uses this list to ensure no R3 reason code falls
    /// off the surface unannounced; the handler files themselves emit the
    /// reasons via the constants above (or wire-level string literals in
    /// the validator path — both satisfy ERR-1 because the constants and
    /// literals share canonical wire form, asserted by
    /// `error::tests::all_r3_reasons_have_a_handler_site`).
    pub const R3_HANDLER_SITES: &[(&str, &str)] = &[
        (
            PAIRING_REQUEST_EXPIRED,
            "routing::identity::agents::lifecycle_transition (provision/pair)",
        ),
        (
            PROOF_INVALID,
            "routing::identity::recovery::validate_recovery_policy auth_data check",
        ),
        (
            VERIFICATION_METHOD_PRINCIPAL_MISMATCH,
            "routing::events::event_log envelope verification_method check",
        ),
        (AGENT_PAUSED, "reducer::apply_agent_lifecycle FSM reject"),
        (
            AGENT_DEACTIVATED,
            "reducer::apply_agent_lifecycle FSM reject",
        ),
        (
            APPROVAL_ALREADY_CONSUMED,
            "routing::identity::agents action_approve idempotency",
        ),
        (
            SIDECAR_CREATE_DENIED,
            "routing::identity::agents::ensure_sidecar_thread",
        ),
        (
            ACTOR_KIND_REDUCER_MANAGED,
            "routing::events::event_log envelope actor_kind reject",
        ),
        (
            FOCUS_MISMATCH,
            "routing::interop::webrtc::handle_rtc_token session_focus check",
        ),
        (
            UNKNOWN_FOCUS_TYPE,
            "routing::events::operations cx.realm.media_service foci[] check",
        ),
        (
            TOKEN_ISSUER_UNAUTHORISED,
            "routing::interop::webrtc::handle_rtc_token issuer_kid resolve",
        ),
        (
            PARTICIPANT_BINDING_INVALID,
            "routing::events::operations cx.call.state participant_binding check",
        ),
        (
            PARTICIPANT_IDENTITY_UNRECOGNISED,
            "routing::interop::webrtc participant identity lookup",
        ),
        (
            SESSION_FOCUS_ALREADY_COMMITTED,
            "routing::events::operations cx.call.state.session_focus write-once",
        ),
        (
            E2EE_KEY_SOURCE_UNAUTHORISED,
            "routing::interop::webrtc e2ee key source authorisation",
        ),
        (
            RECORDING_ARTIFACT_PIPELINE_BYPASSED,
            "routing::interop::webrtc recording artifact pipeline",
        ),
        (
            LEGACY_SINGLE_ENDPOINT_MEDIA_SERVICE,
            "routing::events::operations cx.realm.media_service legacy",
        ),
        (
            FOCUS_UNAVAILABLE_FOR_CLIENT,
            "routing::interop::webrtc focus availability resolution",
        ),
        (
            RECOVERY_WITNESS_REVOKE_LAGGING,
            "routing::identity::recovery::recovery_receipt_put witness freshness",
        ),
        (
            HANDLE_HOMOGRAPH_FORBIDDEN,
            "routing::system::util::classify_handle UTS#39 reject",
        ),
    ];
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

pub use contrix_sdk::ErrorCode;

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

    /// ERR-1 — every R3 reason code in `R3_NEW_REASONS` MUST have a
    /// matching entry in `R3_HANDLER_SITES`. Test scaffolding so a new
    /// reason added to the SDK doesn't silently lack a soland emission
    /// site.
    #[test]
    fn all_r3_reasons_have_a_handler_site() {
        use reasons::{R3_HANDLER_SITES, R3_NEW_REASONS};
        for reason in R3_NEW_REASONS {
            assert!(
                R3_HANDLER_SITES.iter().any(|(r, _)| r == reason),
                "R3 reason `{reason}` lacks a registered handler site \
                 (add to `reasons::R3_HANDLER_SITES` once you wire it)"
            );
        }
        // Symmetric direction: no orphan handler-site entries that
        // don't correspond to a registered R3 reason.
        for (reason, _site) in R3_HANDLER_SITES {
            assert!(
                R3_NEW_REASONS.contains(reason),
                "R3 handler site references unknown reason `{reason}`"
            );
        }
    }

    #[test]
    fn sdk_error_codes_are_soland_source_of_truth() {
        assert_eq!(
            ErrorCode::ALL.len(),
            contrix_sdk::error::KNOWN_ERROR_CODES.len(),
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
}

impl AppError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            status: None,
            wire_code_override: None,
            reason_detail: None,
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
    async fn write(self, _req: &mut Request, _depot: &mut Depot, res: &mut Response) {
        let status = self.http_status();
        let wire = self.wire_code().to_owned();
        if let Some(reason_detail) = self.reason_detail.as_deref() {
            crate::routing::system::util::render_error_with_detail(
                res,
                status,
                &wire,
                &self.message,
                reason_detail,
            );
        } else {
            render_error(res, status, &wire, &self.message);
        }
    }
}

impl EndpointOutRegister for AppError {
    fn register(components: &mut Components, operation: &mut Operation) {
        // Reuse `contrix_sdk::ErrorEnvelope` (already `ToSchema` under the
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
        let envelope_schema = <contrix_sdk::ErrorEnvelope as ToSchema>::to_schema(components);
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
