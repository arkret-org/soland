use super::*;

pub(crate) const MESSAGE_CREATE_FIELDS: &[&str] = &["content", "encrypted_content"];
pub(crate) const MESSAGE_TARGET_FIELDS: &[&str] = &["message_id", "target_ref", "revision_of"];
pub(crate) const MESSAGE_CONTENT_FIELDS: &[&str] = &["content", "encrypted_content"];
pub(crate) const REDACTION_TARGET_FIELDS: &[&str] = &["target_event_id", "target", "redacts"];
pub(crate) const REACTION_TARGET_FIELDS: &[&str] = &[
    "target_ref",
    "event_id",
    "target_event_id",
    "message_id",
    "target_message_id",
];
pub(crate) const REACTION_ACTOR_FIELDS: &[&str] = &["actor", "sender"];
pub(crate) const REACTION_KEY_FIELDS: &[&str] = &["key", "reaction", "reaction_key"];
pub(crate) const RELATION_ID_FIELDS: &[&str] = &["relation_id", "id"];
pub(crate) const RELATION_KIND_FIELDS: &[&str] = &["relation_kind", "kind"];
pub(crate) const RELATION_FROM_FIELDS: &[&str] = &["from_ref", "from"];
pub(crate) const RELATION_TO_FIELDS: &[&str] = &["to_ref", "to"];
pub(crate) const MEMBER_ACTOR_FIELDS: &[&str] = &["actor_id", "member", "actor", "sender"];
pub(crate) const INVITE_CREATE_TARGET_FIELDS: &[&str] = &["invitee", "actor_id", "member"];
pub(crate) const INVITE_THIRD_PARTY_FIELDS: &[&str] = &["invite", "third_party_id"];
pub(crate) const READ_MARKER_ACTOR_FIELDS: &[&str] = &["actor_id"];
pub(crate) const CONSENT_PEER_FIELDS: &[&str] = &["peer", "peer_did", "grantee_did"];
pub(crate) const CONSENT_SCOPE_FIELDS: &[&str] = &["consent_scope", "scope"];
pub(crate) const MLS_COMMIT_GROUP_FIELDS: &[&str] = &["group_id", "mls_group_id"];
pub(crate) const MLS_COMMIT_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::AnyOf(
    MLS_COMMIT_GROUP_FIELDS,
    "ck.mls.commit requires group_id for reducer projection",
)];
pub(crate) const MLS_GENESIS_GROUP_FIELDS: &[&str] = &["group_id", "mls_group_id"];
pub(crate) const MLS_GENESIS_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::AnyOf(
    MLS_GENESIS_GROUP_FIELDS,
    "ck.mls.genesis requires mls_group_id for reducer projection",
)];
pub(crate) const MLS_WELCOME_GROUP_FIELDS: &[&str] = &["group_id", "mls_group_id"];
pub(crate) const MLS_WELCOME_RECIPIENT_FIELDS: &[&str] =
    &["recipient_actor_id", "recipient_principal_id"];
pub(crate) const MLS_WELCOME_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::AnyOf(
        MLS_WELCOME_GROUP_FIELDS,
        "ck.mls.welcome requires mls_group_id for reducer projection",
    ),
    PayloadRequirement::AnyOf(
        MLS_WELCOME_RECIPIENT_FIELDS,
        "ck.mls.welcome requires recipient principal for reducer projection",
    ),
];
pub(crate) const MLS_KEYPACKAGE_ACTION_FIELDS: &[&str] = &["action", "state"];
pub(crate) const MLS_KEYPACKAGE_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::AnyOf(
    MLS_KEYPACKAGE_ACTION_FIELDS,
    "ck.mls.keypackage requires action/state for reducer projection",
)];

pub(crate) const MESSAGE_CREATE_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::AnyOf(
    MESSAGE_CREATE_FIELDS,
    "message operation requires body, content, or event_id",
)];
pub(crate) const MESSAGE_REVISE_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::AnyOf(
        MESSAGE_TARGET_FIELDS,
        "message revision requires message_id, target_ref, or revision_of",
    ),
    PayloadRequirement::AnyOf(
        MESSAGE_CONTENT_FIELDS,
        "message revision requires content or encrypted_content",
    ),
];
pub(crate) const REDACTION_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::AnyOf(
    REDACTION_TARGET_FIELDS,
    "redaction operation requires target_event_id",
)];
pub(crate) const REACTION_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::AnyOf(
        REACTION_TARGET_FIELDS,
        "reaction operation requires target event",
    ),
    PayloadRequirement::AnyOf(REACTION_ACTOR_FIELDS, "reaction operation requires actor"),
    PayloadRequirement::AnyOf(
        REACTION_KEY_FIELDS,
        "reaction operation requires reaction key",
    ),
];
pub(crate) const RELATION_CREATE_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::AnyOf(
        RELATION_ID_FIELDS,
        "relation operation requires relation_id",
    ),
    PayloadRequirement::AnyOf(
        RELATION_KIND_FIELDS,
        "relation create requires relation_kind",
    ),
    PayloadRequirement::AnyOf(RELATION_FROM_FIELDS, "relation create requires from"),
    PayloadRequirement::AnyOf(RELATION_TO_FIELDS, "relation create requires to"),
];
pub(crate) const RELATION_ID_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::AnyOf(
    RELATION_ID_FIELDS,
    "relation operation requires relation_id",
)];
// G3.S5 — `ck.realm.link` Move payload. The wire schema also permits
// `status` / `label` / `commitment`, but those are optional and the
// reducer assigns defaults. Required fields only.
pub(crate) const REALM_LINK_TARGET_FIELDS: &[&str] = &["target_realm_id"];
pub(crate) const REALM_LINK_KIND_FIELDS: &[&str] = &["link_kind"];
pub(crate) const REALM_LINK_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::AnyOf(
        REALM_LINK_TARGET_FIELDS,
        "ck.realm.link requires target_realm_id",
    ),
    PayloadRequirement::AnyOf(REALM_LINK_KIND_FIELDS, "ck.realm.link requires link_kind"),
];
pub(crate) const CAPABILITY_GRANT_ID_FIELDS: &[&str] = &["grant_id"];
pub(crate) const CAPABILITY_GRANT_REQUIREMENTS: &[PayloadRequirement] =
    &[PayloadRequirement::AnyOf(
        CAPABILITY_GRANT_ID_FIELDS,
        "capability lifecycle operation requires grant_id",
    )];
pub(crate) const VIEW_ID_FIELDS: &[&str] = &["view_id"];
pub(crate) const VIEW_CREATE_REQUIREMENTS: &[PayloadRequirement] = &[PayloadRequirement::AnyOf(
    VIEW_ID_FIELDS,
    "view operation requires view_id",
)];
pub(crate) const MEMBERSHIP_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::AnyOf(MEMBER_ACTOR_FIELDS, "membership operation requires member"),
    PayloadRequirement::Required(
        "membership",
        "membership operation requires member and membership",
    ),
];
pub(crate) const INVITE_CREATE_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("invite_id", "ck.invite.create operation requires invite_id"),
    PayloadRequirement::AnyOf(
        INVITE_CREATE_TARGET_FIELDS,
        "ck.invite.create operation requires invitee",
    ),
    PayloadRequirement::Required(
        "invite_delivery_target",
        "ck.invite.create operation requires invite_delivery_target",
    ),
    PayloadRequirement::Required(
        "introduction_evidence_digest",
        "ck.invite.create operation requires introduction_evidence_digest",
    ),
    PayloadRequirement::Required(
        "expires_at",
        "ck.invite.create operation requires expires_at",
    ),
];
pub(crate) const INVITE_THIRD_PARTY_REQUIREMENTS: &[PayloadRequirement] =
    &[PayloadRequirement::AnyOf(
        INVITE_THIRD_PARTY_FIELDS,
        "ck.invite.third_party requires invite or third_party_id",
    )];
pub(crate) const INVITE_CLAIM_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("invite_id", "ck.invite.claim requires invite_id"),
    PayloadRequirement::Required("subject_id", "ck.invite.claim requires subject_id"),
    PayloadRequirement::Required(
        "token_commitment",
        "ck.invite.claim requires token_commitment",
    ),
    PayloadRequirement::Required("claim_nonce", "ck.invite.claim requires claim_nonce"),
    PayloadRequirement::Required("binding_proof", "ck.invite.claim requires binding_proof"),
    PayloadRequirement::Required("subject_proof", "ck.invite.claim requires subject_proof"),
];
pub(crate) const INVITE_STATE_REQUIREMENTS: &[PayloadRequirement] = &[];
pub(crate) const REALM_CREATE_REQUIREMENTS: &[PayloadRequirement] =
    &[PayloadRequirement::Required(
        "object",
        "ck.realm.create operation requires payload.object",
    )];
pub(crate) const REALM_UPDATE_REQUIREMENTS: &[PayloadRequirement] =
    &[PayloadRequirement::Required(
        "patch",
        "ck.realm.update operation requires patch",
    )];
pub(crate) const REALM_ARCHIVE_REQUIREMENTS: &[PayloadRequirement] =
    &[PayloadRequirement::Required(
        "archived",
        "ck.realm.archive operation requires archived",
    )];
pub(crate) const REALM_FREEZE_REQUIREMENTS: &[PayloadRequirement] =
    &[PayloadRequirement::Required(
        "frozen",
        "ck.realm.freeze operation requires frozen",
    )];
pub(crate) const REALM_TERMINAL_REQUIREMENTS: &[PayloadRequirement] = &[];
pub(crate) const REALM_MODERATION_POLICY_REQUIREMENTS: &[PayloadRequirement] = &[];
pub(crate) const REALM_POLICY_VALUE_REQUIREMENTS: &[PayloadRequirement] =
    &[PayloadRequirement::Required(
        "value",
        "realm policy event requires value",
    )];
pub(crate) const REALM_DISAPPEARING_POLICY_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("enabled", "ck.realm.disappearing_policy requires enabled"),
    PayloadRequirement::Required(
        "max_ttl_ms",
        "ck.realm.disappearing_policy requires max_ttl_ms",
    ),
    PayloadRequirement::Required(
        "allowed_triggers",
        "ck.realm.disappearing_policy requires allowed_triggers",
    ),
];
pub(crate) const REALM_SEARCH_POLICY_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required(
        "enabled_profile_refs",
        "ck.realm.search_policy requires enabled_profile_refs",
    ),
    PayloadRequirement::Required(
        "allowed_service_dids",
        "ck.realm.search_policy requires allowed_service_dids",
    ),
    PayloadRequirement::Required(
        "data_classes",
        "ck.realm.search_policy requires data_classes",
    ),
];
pub(crate) const MODERATION_DECISION_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("target_ref", "ck.moderation.decision requires target_ref"),
    PayloadRequirement::Required("decision", "ck.moderation.decision requires decision"),
    PayloadRequirement::Required("issuer", "ck.moderation.decision requires issuer"),
    PayloadRequirement::Required(
        "request_canonical_digest",
        "ck.moderation.decision requires request_canonical_digest",
    ),
];
pub(crate) const MODERATION_DECISION_LIFT_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required(
        "target_ref",
        "ck.moderation.decision.lift requires target_ref",
    ),
    PayloadRequirement::Required(
        "decision_ref",
        "ck.moderation.decision.lift requires decision_ref",
    ),
];
pub(crate) const MODERATION_APPEAL_SUBMIT_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required(
        "appeal_id",
        "ck.moderation.appeal.submit requires appeal_id",
    ),
    PayloadRequirement::Required("realm_id", "ck.moderation.appeal.submit requires realm_id"),
    PayloadRequirement::Required(
        "decision_ref",
        "ck.moderation.appeal.submit requires decision_ref",
    ),
    PayloadRequirement::Required(
        "target_ref",
        "ck.moderation.appeal.submit requires target_ref",
    ),
    PayloadRequirement::Required(
        "appellant",
        "ck.moderation.appeal.submit requires appellant",
    ),
    PayloadRequirement::Required(
        "reason_text_ref",
        "ck.moderation.appeal.submit requires reason_text_ref",
    ),
    PayloadRequirement::Required(
        "created_at",
        "ck.moderation.appeal.submit requires created_at",
    ),
];
pub(crate) const MODERATION_APPEAL_REVIEW_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required(
        "appeal_id",
        "ck.moderation.appeal.review requires appeal_id",
    ),
    PayloadRequirement::Required("realm_id", "ck.moderation.appeal.review requires realm_id"),
    PayloadRequirement::Required("reviewer", "ck.moderation.appeal.review requires reviewer"),
    PayloadRequirement::Required(
        "reviewed_at",
        "ck.moderation.appeal.review requires reviewed_at",
    ),
];
pub(crate) const MODERATION_APPEAL_DECISION_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required(
        "appeal_id",
        "ck.moderation.appeal.decision requires appeal_id",
    ),
    PayloadRequirement::Required(
        "realm_id",
        "ck.moderation.appeal.decision requires realm_id",
    ),
    PayloadRequirement::Required(
        "reviewer",
        "ck.moderation.appeal.decision requires reviewer",
    ),
    PayloadRequirement::Required("verdict", "ck.moderation.appeal.decision requires verdict"),
    PayloadRequirement::Required(
        "reason_text_ref",
        "ck.moderation.appeal.decision requires reason_text_ref",
    ),
    PayloadRequirement::Required(
        "decided_at",
        "ck.moderation.appeal.decision requires decided_at",
    ),
];
pub(crate) const MODERATION_APPEAL_CLOSE_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("appeal_id", "ck.moderation.appeal.close requires appeal_id"),
    PayloadRequirement::Required("realm_id", "ck.moderation.appeal.close requires realm_id"),
    PayloadRequirement::Required("closer", "ck.moderation.appeal.close requires closer"),
    PayloadRequirement::Required("closed_at", "ck.moderation.appeal.close requires closed_at"),
];
pub(crate) const CONFLICT_REPAIR_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("cell_id", "conflict repair requires cell_id"),
    PayloadRequirement::Required("conflict_heads", "conflict repair requires conflict_heads"),
    PayloadRequirement::Required("winner_value", "conflict repair requires winner_value"),
    PayloadRequirement::Required(
        "recovery_capability_ref",
        "conflict repair requires recovery_capability_ref",
    ),
    PayloadRequirement::Required(
        "state_witness_ref",
        "conflict repair requires state_witness_ref",
    ),
];
// `ck.space.archive` / `ck.space.restore` / `ck.space.tombstone` share the
// spec-canonical `space_id` target field.
pub(crate) const SPACE_CONTAINER_LIFECYCLE_ID_FIELDS: &[&str] = &["space_id"];
pub(crate) const SPACE_CONTAINER_LIFECYCLE_REQUIREMENTS: &[PayloadRequirement] =
    &[PayloadRequirement::AnyOf(
        SPACE_CONTAINER_LIFECYCLE_ID_FIELDS,
        "space lifecycle operation requires space_id",
    )];
// `ck.space.create` carries a full Space object under `object`.
pub(crate) const SPACE_CONTAINER_CREATE_REQUIREMENTS: &[PayloadRequirement] =
    &[PayloadRequirement::Required(
        "object",
        "space create operation requires object",
    )];
// `ck.space.update` carries the canonical Space target field plus patch.
pub(crate) const SPACE_CONTAINER_UPDATE_ID_FIELDS: &[&str] = &["space_id"];
pub(crate) const SPACE_CONTAINER_UPDATE_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::AnyOf(
        SPACE_CONTAINER_UPDATE_ID_FIELDS,
        "space update operation requires space_id",
    ),
    PayloadRequirement::Required("patch", "space update operation requires patch"),
];
// `ck.space.parent` carries `space_id` + `expected_parent_space_id`, with
// optional `parent_space_id`.
pub(crate) const SPACE_CONTAINER_PARENT_ID_FIELDS: &[&str] = &["space_id"];
pub(crate) const SPACE_CONTAINER_PARENT_EXPECTED_FIELDS: &[&str] = &["expected_parent_space_id"];
pub(crate) const SPACE_CONTAINER_PARENT_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::AnyOf(
        SPACE_CONTAINER_PARENT_ID_FIELDS,
        "space parent operation requires space_id",
    ),
    PayloadRequirement::AnyKey(
        SPACE_CONTAINER_PARENT_EXPECTED_FIELDS,
        "space parent operation requires expected_parent_space_id",
    ),
];
// Strand lifecycle uses the generic `object_lifecycle_payload`: target_ref is
// the single source for the target Strand.
pub(crate) const STRAND_LIFECYCLE_ID_FIELDS: &[&str] = &["target_ref"];
pub(crate) const STRAND_LIFECYCLE_REQUIREMENTS: &[PayloadRequirement] =
    &[PayloadRequirement::AnyOf(
        STRAND_LIFECYCLE_ID_FIELDS,
        "strand lifecycle operation requires target_ref",
    )];
pub(crate) const STRAND_CREATE_REQUIREMENTS: &[PayloadRequirement] =
    &[PayloadRequirement::Required(
        "object",
        "strand create operation requires object",
    )];
pub(crate) const STRAND_UPDATE_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::AnyOf(
        &["target_ref"],
        "strand update operation requires target_ref",
    ),
    PayloadRequirement::Required("patch", "strand update operation requires patch"),
];
// `ck.morph.archive` / `ck.morph.restore` use the generic object lifecycle
// payload shape: target_ref names the Morph.
pub(crate) const MORPH_LIFECYCLE_REQUIREMENTS: &[PayloadRequirement] =
    &[PayloadRequirement::Required(
        "target_ref",
        "morph lifecycle operation requires target_ref",
    )];
pub(crate) const MORPH_CREATE_REQUIREMENTS: &[PayloadRequirement] =
    &[PayloadRequirement::Required(
        "object",
        "morph create operation requires object",
    )];
pub(crate) const MORPH_UPDATE_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::AnyOf(
        &["target_ref"],
        "morph update operation requires target_ref",
    ),
    PayloadRequirement::Required("patch", "morph update operation requires patch"),
];
pub(crate) const MORPH_SCHEMA_MIGRATE_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required(
        "morph_id",
        "morph schema_migrate operation requires morph_id",
    ),
    PayloadRequirement::Required(
        "from_schema_refs",
        "morph schema_migrate operation requires from_schema_refs",
    ),
    PayloadRequirement::Required(
        "to_schema_refs",
        "morph schema_migrate operation requires to_schema_refs",
    ),
    PayloadRequirement::Required(
        "compatibility_class",
        "morph schema_migrate operation requires compatibility_class",
    ),
];
// Strand position events (ck.strand.move / ck.strand.reorder).
pub(crate) const STRAND_POSITION_BOARD_FIELDS: &[&str] = &["board_space_id"];
pub(crate) const STRAND_MOVE_TARGET_FIELDS: &[&str] = &["target_space_id"];
pub(crate) const STRAND_REORDER_SPACE_FIELDS: &[&str] = &["space_id", "list_space_id"];
pub(crate) const STRAND_MOVE_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("strand_id", "strand position operation requires strand_id"),
    PayloadRequirement::AnyOf(
        STRAND_POSITION_BOARD_FIELDS,
        "strand position operation requires board_space_id",
    ),
    PayloadRequirement::AnyOf(
        STRAND_MOVE_TARGET_FIELDS,
        "strand move operation requires target_space_id",
    ),
    PayloadRequirement::Required("rank", "strand move operation requires rank"),
];
pub(crate) const STRAND_REORDER_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("strand_id", "strand position operation requires strand_id"),
    PayloadRequirement::AnyOf(
        STRAND_POSITION_BOARD_FIELDS,
        "strand position operation requires board_space_id",
    ),
    PayloadRequirement::AnyOf(
        STRAND_REORDER_SPACE_FIELDS,
        "strand reorder operation requires space_id",
    ),
    PayloadRequirement::Required("rank", "strand reorder operation requires rank"),
];
// Strand watch event (ck.strand.watch.set).
// Spec event-kind-registry sets `cell_subject` = (strand_id, watcher_actor_id);
// both fields are MUST-present in the payload. `level` is also required
// (null = clear); enum + level_public validation lives at the
// strand_watch_set_payload schema layer.
pub(crate) const STRAND_WATCH_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("strand_id", "strand watch operation requires strand_id"),
    PayloadRequirement::Required(
        "watcher_actor_id",
        "strand watch operation requires watcher_actor_id",
    ),
    PayloadRequirement::Required(
        "level",
        "strand watch operation requires level (use null to clear)",
    ),
];
// Strand tracks update event. Required fields per SDK schema:
//   `ck.strand.tracks.update` -> strand_id + (patch | tracks)
pub(crate) const STRAND_TRACKS_UPDATE_FIELDS: &[&str] = &["patch", "tracks"];
pub(crate) const STRAND_TRACKS_UPDATE_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("strand_id", "strand tracks update requires strand_id"),
    PayloadRequirement::AnyOf(
        STRAND_TRACKS_UPDATE_FIELDS,
        "strand tracks update requires patch or tracks",
    ),
];
// Applet protocol family.
//
// Spec `extensions/applet-integration.md` + event-kind-registry rows:
//   `ck.applet.registration` → service_did + namespace + capabilities
//   `ck.applet.discovery`    → service_did + manifest
//   `ck.applet.interop_session.start`  → applet_id + session_id + params
//   `ck.applet.interop_session.status` → session_id + status + detail
//   `ck.applet.bridge_error`            → session_id + errcode + message
//
// We require the structurally-identifying fields; richer policy
// (capability gating, manifest schema, signed bundles) is enforced by
// the applet bridge layer + per-applet contract validators that read
// the payload after admission.
pub(crate) const APPLET_REGISTRATION_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("service_did", "applet registration requires service_did"),
    PayloadRequirement::Required("namespace", "applet registration requires namespace"),
];
pub(crate) const APPLET_DISCOVERY_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("service_did", "applet discovery requires service_did"),
    PayloadRequirement::Required("manifest", "applet discovery requires manifest"),
];
pub(crate) const APPLET_SESSION_START_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required(
        "applet_id",
        "applet interop_session.start requires applet_id",
    ),
    PayloadRequirement::Required(
        "session_id",
        "applet interop_session.start requires session_id",
    ),
];
pub(crate) const APPLET_SESSION_STATUS_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required(
        "session_id",
        "applet interop_session.status requires session_id",
    ),
    PayloadRequirement::Required("status", "applet interop_session.status requires status"),
];
pub(crate) const APPLET_BRIDGE_ERROR_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("session_id", "applet bridge_error requires session_id"),
    PayloadRequirement::Required("errcode", "applet bridge_error requires errcode"),
];

// Agent protocol family. Mirror of applet but with a terminal
// `*.result` event that carries the audit-binding proof + signed agent
// result.
pub(crate) const AGENT_ENDPOINT_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("agent_id", "agent endpoint requires agent_id"),
    PayloadRequirement::Required("endpoints", "agent endpoint requires endpoints"),
];
pub(crate) const AGENT_SESSION_START_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required(
        "session_id",
        "agent interop_session.start requires session_id",
    ),
    PayloadRequirement::Required(
        "counterparty_agent",
        "agent interop_session.start requires counterparty_agent",
    ),
    PayloadRequirement::Required("protocol", "agent interop_session.start requires protocol"),
    PayloadRequirement::Required(
        "capability_grant",
        "agent interop_session.start requires capability_grant",
    ),
];
pub(crate) const AGENT_SESSION_STATUS_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required(
        "session_id",
        "agent interop_session.status requires session_id",
    ),
    PayloadRequirement::Required("status", "agent interop_session.status requires status"),
];
pub(crate) const AGENT_SESSION_RESULT_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required(
        "session_id",
        "agent interop_session.result requires session_id",
    ),
    PayloadRequirement::Required("result", "agent interop_session.result requires result"),
    PayloadRequirement::Required(
        "audit_binding",
        "agent interop_session.result requires audit_binding",
    ),
];

// R3 spec-sync (2026-05-27) — agent lifecycle FSM payloads. Wire
// shape per spec `agent_pause_payload` / `agent_resume_payload` /
// `agent_deactivate_payload`. The FSM transition guard runs in the
// reducer (REDU-1, `apply_agent_lifecycle`).
pub(crate) const AGENT_PAUSE_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required(
        "agent_principal_id",
        "ck.self.agent.pause requires agent_principal_id",
    ),
    PayloadRequirement::Required(
        "status_changed_at",
        "ck.self.agent.pause requires status_changed_at",
    ),
];
pub(crate) const AGENT_RESUME_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required(
        "agent_principal_id",
        "ck.self.agent.resume requires agent_principal_id",
    ),
    PayloadRequirement::Required(
        "status_changed_at",
        "ck.self.agent.resume requires status_changed_at",
    ),
];
pub(crate) const AGENT_DEACTIVATE_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required(
        "agent_principal_id",
        "ck.self.agent.deactivate requires agent_principal_id",
    ),
    PayloadRequirement::Required(
        "status_changed_at",
        "ck.self.agent.deactivate requires status_changed_at",
    ),
];

// R3 spec-sync — `actor_private_event` payloads. These do NOT advance
// the seal frontier / actor_seq (reducer_input=false).
pub(crate) const AGENT_DRAFT_PROPOSE_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required(
        "agent_principal_id",
        "ck.agent.draft.propose requires agent_principal_id",
    ),
    PayloadRequirement::Required("draft_id", "ck.agent.draft.propose requires draft_id"),
];
pub(crate) const AGENT_ACTION_REQUEST_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required(
        "agent_principal_id",
        "ck.agent.action_request requires agent_principal_id",
    ),
    PayloadRequirement::Required("request_id", "ck.agent.action_request requires request_id"),
];
pub(crate) const AGENT_ACTION_APPROVE_REQUIREMENTS: &[PayloadRequirement] =
    &[PayloadRequirement::AnyOf(
        &["request_id", "draft_id"],
        "ck.agent.action_approve requires request_id or draft_id",
    )];
pub(crate) const AGENT_ACTION_REJECT_REQUIREMENTS: &[PayloadRequirement] =
    &[PayloadRequirement::AnyOf(
        &["request_id", "draft_id"],
        "ck.agent.action_reject requires request_id or draft_id",
    )];

pub(crate) const CROSS_SIGNING_RESET_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("principal_id", "cross_signing reset requires principal_id"),
    PayloadRequirement::Required(
        "previous_generation",
        "cross_signing reset requires previous_generation",
    ),
    PayloadRequirement::Required(
        "new_generation",
        "cross_signing reset requires new_generation",
    ),
    PayloadRequirement::Required(
        "reset_reason_code",
        "cross_signing reset requires reset_reason_code",
    ),
    PayloadRequirement::Required("proof", "cross_signing reset requires proof"),
    PayloadRequirement::Required("issued_at", "cross_signing reset requires issued_at"),
    // Round R2/R3 (T08) — wire-breaking required fields.
    PayloadRequirement::Required(
        "trust_domain",
        "cross_signing reset requires trust_domain (Round R2/R3 wire-break)",
    ),
    PayloadRequirement::Required(
        "reset_event_id",
        "cross_signing reset requires reset_event_id (Round R2/R3 wire-break)",
    ),
];

pub(crate) const CROSS_SIGNING_PUBLISH_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required(
        "principal_id",
        "cross_signing publish requires principal_id",
    ),
    PayloadRequirement::Required(
        "trust_domain",
        "cross_signing publish requires trust_domain",
    ),
    PayloadRequirement::Required(
        "principal_signing_key",
        "cross_signing publish requires principal_signing_key",
    ),
    PayloadRequirement::Required(
        "self_signing_key",
        "cross_signing publish requires self_signing_key",
    ),
    PayloadRequirement::Required(
        "user_signing_key",
        "cross_signing publish requires user_signing_key",
    ),
    PayloadRequirement::Required("generation", "cross_signing publish requires generation"),
    PayloadRequirement::Required(
        "expected_previous_generation",
        "cross_signing publish requires expected_previous_generation",
    ),
    PayloadRequirement::Required("issued_at", "cross_signing publish requires issued_at"),
];

pub(crate) const DEVICE_AUTHORIZE_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("principal_id", "ck.device.authorize requires principal_id"),
    PayloadRequirement::Required("device_id", "ck.device.authorize requires device_id"),
];

pub(crate) const READ_MARKER_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::AnyOf(
        READ_MARKER_ACTOR_FIELDS,
        "read marker operation requires actor",
    ),
    PayloadRequirement::Required("read_scope", "read marker operation requires read_scope"),
    PayloadRequirement::Required("position", "read marker operation requires position"),
];
pub(crate) const ACCOUNT_DATA_VALUE_FIELDS: &[&str] = &[
    "body",
    "encrypted_payload",
    "encrypted_content",
    "tombstone",
];
pub(crate) const ACCOUNT_DATA_SET_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("owner", "account_data.set requires owner"),
    PayloadRequirement::Required("key", "account_data.set requires key"),
    PayloadRequirement::AnyOf(
        ACCOUNT_DATA_VALUE_FIELDS,
        "account_data.set requires body, encrypted_payload, or tombstone",
    ),
];
pub(crate) const RSVP_SET_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("event_ref", "ck.rsvp.set requires event_ref"),
    PayloadRequirement::Required("status", "ck.rsvp.set requires status"),
    PayloadRequirement::AnyKey(&["occurrence"], "ck.rsvp.set requires occurrence"),
];
pub(crate) const PIN_ADD_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("pin_scope", "ck.pin.add requires pin_scope"),
    PayloadRequirement::Required("target_ref", "ck.pin.add requires target_ref"),
    PayloadRequirement::Required("rank", "ck.pin.add requires rank"),
];
pub(crate) const PIN_REMOVE_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("pin_scope", "ck.pin.remove requires pin_scope"),
    PayloadRequirement::Required("target_ref", "ck.pin.remove requires target_ref"),
];
pub(crate) const PIN_REORDER_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("pin_scope", "ck.pin.reorder requires pin_scope"),
    PayloadRequirement::Required("target_ref", "ck.pin.reorder requires target_ref"),
    PayloadRequirement::Required("rank", "ck.pin.reorder requires rank"),
];
pub(crate) const CONSENT_GRANT_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("consent_id", "consent grant requires consent_id"),
    PayloadRequirement::AnyOf(CONSENT_PEER_FIELDS, "consent grant requires peer"),
    PayloadRequirement::AnyOf(CONSENT_SCOPE_FIELDS, "consent grant requires scope"),
];
pub(crate) const CONSENT_REVOKE_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("consent_id", "consent revoke requires consent_id"),
    PayloadRequirement::Required("observed_dots", "consent revoke requires observed_dots"),
];
pub(crate) const ERASURE_RECEIPT_REQUIREMENTS: &[PayloadRequirement] = &[
    PayloadRequirement::Required("receipt_id", "erasure receipt requires receipt_id"),
    PayloadRequirement::Required("subject", "erasure receipt requires subject"),
    PayloadRequirement::Required("scope", "erasure receipt requires scope"),
    PayloadRequirement::Required("outcome", "erasure receipt requires outcome"),
];
