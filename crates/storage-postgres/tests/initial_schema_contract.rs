const INITIAL_UP: &str = include_str!("../migrations/00000000000000_initial/up.sql");
const INITIAL_DOWN: &str = include_str!("../migrations/00000000000000_initial/down.sql");

#[test]
fn capability_authority_root_is_durable_and_distinct_from_station_tenure() {
    assert!(INITIAL_UP.contains("CREATE TABLE realm_authority_root_current_results"));
    for column in [
        "controller_actor_id JSONB NOT NULL",
        "controller_epoch BIGINT NOT NULL",
        "authority_generation BIGINT NOT NULL",
        "authority_event_ref TEXT NOT NULL",
        "current_commit_id TEXT NOT NULL",
        "current_stream_position BIGINT NOT NULL",
    ] {
        assert!(
            INITIAL_UP.contains(column),
            "missing authority-root column {column}"
        );
    }
    assert!(INITIAL_UP.contains("CREATE TABLE public.realm_authorities"));
    assert!(INITIAL_DOWN.contains("DROP TABLE IF EXISTS realm_authority_root_current_results"));
}

#[test]
fn parent_membership_inputs_are_authoritative_typed_current_results() {
    for table in [
        "realm_policy_bundle_current_results",
        "realm_link_current_results",
        "member_state_current_results",
    ] {
        assert!(INITIAL_UP.contains(&format!("CREATE TABLE {table}")));
        assert!(INITIAL_DOWN.contains(&format!("DROP TABLE IF EXISTS {table}")));
    }
    assert!(INITIAL_UP.contains("PRIMARY KEY(realm_id,target_realm_id,link_kind)"));
    assert!(INITIAL_UP.contains("PRIMARY KEY(realm_id,member_id)"));
}

#[test]
fn agent_draft_pending_intent_is_a_separate_private_state_machine() {
    assert!(INITIAL_UP.contains("CREATE TABLE public.agent_draft_pending_intents"));
    assert!(
        INITIAL_UP.contains("PRIMARY KEY\n        (controller_account_key, agent_id, draft_id)")
    );
    assert!(INITIAL_UP.contains("state IN ('available', 'consumed', 'expired')"));
    assert!(INITIAL_UP.contains("agent_draft_pending_intents_terminal_shape_check"));
    assert!(INITIAL_UP.contains("state = 'available' AND content_handoff IS NOT NULL"));
    assert!(INITIAL_UP.contains("state = 'consumed' AND content_handoff IS NULL"));
    assert!(INITIAL_UP.contains("state = 'expired' AND content_handoff IS NULL"));
    assert!(INITIAL_UP.contains("CREATE FUNCTION project_agent_draft_pending_intent()"));
    assert!(INITIAL_UP.contains("CREATE TABLE account_global_channel_clocks"));
    assert!(INITIAL_UP.contains("channel_position BIGINT NOT NULL"));
    assert!(INITIAL_UP.contains("'agent_draft_pending_intents'"));
    assert!(INITIAL_UP.contains("CREATE TRIGGER account_global_agent_draft_pending_intent"));
    assert!(INITIAL_UP.contains("CREATE TRIGGER preserve_agent_draft_pending_intent_identity"));
    assert!(INITIAL_DOWN.contains("DROP FUNCTION IF EXISTS project_agent_draft_pending_intent()"));
    assert!(
        INITIAL_DOWN.contains("DROP FUNCTION IF EXISTS reject_agent_draft_pending_intent_delete()")
    );
    assert!(INITIAL_DOWN.contains("DROP TABLE IF EXISTS agent_draft_pending_intents CASCADE"));
    assert!(INITIAL_DOWN.contains("DROP TABLE IF EXISTS account_global_channel_clocks"));
}

#[test]
fn actor_private_effects_share_one_exact_retry_ledger_outside_realm_history() {
    assert!(INITIAL_UP.contains("CREATE TABLE public.read_cursor_winners"));
    assert!(INITIAL_UP.contains(
        "CONSTRAINT read_cursor_winners_pk PRIMARY KEY (account_key, realm_id, read_scope_key)"
    ));
    assert!(INITIAL_UP.contains("CREATE TABLE public.actor_private_events"));
    assert!(INITIAL_UP.contains("(kind <> 'ak.account_data.set') = (outcome IS NOT NULL)"));
    assert!(INITIAL_UP.contains("CREATE TABLE public.device_push_routes"));
    assert!(INITIAL_UP.contains("CREATE TABLE public.agent_action_requests"));
    assert!(INITIAL_UP.contains("CREATE TABLE public.agent_action_rejections"));
    assert!(INITIAL_DOWN.contains("DROP TABLE IF EXISTS device_push_routes CASCADE"));
    assert!(INITIAL_DOWN.contains("DROP TABLE IF EXISTS actor_private_events CASCADE"));
    assert!(INITIAL_DOWN.contains("DROP TABLE IF EXISTS read_cursor_winners CASCADE"));
    assert!(!INITIAL_UP.contains("canonical_account_data_source_id"));
    assert!(INITIAL_UP.contains("OR NOT EXISTS(SELECT 1 FROM actor_private_events e"));
}

#[test]
fn history_response_stream_tables_are_created_and_dropped_symmetrically() {
    for table in [
        "history_key_response_streams",
        "history_key_responses",
        "history_key_response_ack_tokens",
        "history_key_response_dispositions",
        "history_key_response_tombstones",
    ] {
        assert!(INITIAL_UP.contains(&format!("CREATE TABLE public.{table}")));
        assert!(INITIAL_DOWN.contains(&format!("DROP TABLE IF EXISTS public.{table}")));
    }

    assert!(INITIAL_UP.contains("CREATE INDEX history_key_requests_local_sequence_idx"));
    assert!(INITIAL_UP.contains("WHERE request_replica_digest IS NULL"));
}

#[test]
fn agent_principal_constraints_use_spec_identifier_kinds() {
    let did_core_check = "^ak:did_core:webvh:[^[:space:]/:#?]+$";
    let delegation_check = "^did:webvh:[^[:space:]/:#?]+:[^[:space:]/?#]+#managed-controller$";

    assert!(INITIAL_UP.contains(did_core_check));
    assert!(INITIAL_UP.contains(delegation_check));
    assert!(
        INITIAL_UP.contains(
            "id = 'ak:did_core:webvh:' || split_part(controller_authorization_ref, ':', 3)"
        ) || INITIAL_UP.contains(
            "id = ('ak:did_core:webvh:'::text || split_part(controller_authorization_ref, ':'::text, 3))"
        )
    );
    assert!(!INITIAL_UP.contains("controller_authorization_ref LIKE (id || '#%')"));
    assert!(!INITIAL_UP.contains("controller_authorization_ref ~~ (id || '#%'"));
}

#[test]
fn circle_join_rule_constraint_uses_spec_vocabulary() {
    assert!(INITIAL_UP.contains("ARRAY['invite'::text, 'knock'::text, 'public'::text]"));
    assert!(!INITIAL_UP.contains("ARRAY['invite'::text, 'request'::text, 'open'::text]"));
}

#[test]
fn applet_identity_winner_is_independent_from_exact_scope_installations() {
    assert!(INITIAL_UP.contains("CREATE TABLE public.applet_managed_identities"));
    assert!(INITIAL_UP.contains("PRIMARY KEY (applet_id, target_station_id)"));
    assert!(INITIAL_UP.contains("CREATE TABLE public.applet_installations"));
    assert!(INITIAL_UP.contains("PRIMARY KEY (applet_id, effective_scope_key)"));
    assert!(INITIAL_UP.contains("NOT (record ?| ARRAY["));
    assert!(INITIAL_UP.contains("'bot_actor_id'")); // retired install-level identity is forbidden
    assert!(INITIAL_UP.contains("record->>'target_station_id' = target_station_id"));
    assert!(INITIAL_UP.contains("request_body jsonb NOT NULL"));
    assert!(INITIAL_UP.contains("'globally_fenced_at'"));
    assert!(INITIAL_DOWN.contains("DROP TABLE IF EXISTS applet_managed_identities CASCADE"));
}

#[test]
fn seal_effective_state_checkpoint_is_created_and_dropped_symmetrically() {
    assert!(INITIAL_UP.contains("CREATE TABLE public.state_seal_effective_checkpoints"));
    assert!(INITIAL_UP.contains("covered_event_digests text[] NOT NULL"));
    assert!(INITIAL_UP.contains("covered_seal_ids text[] NOT NULL"));
    assert!(INITIAL_UP.contains("state_seal_effective_checkpoints_immutable"));
    assert!(INITIAL_DOWN.contains("DROP TABLE IF EXISTS state_seal_effective_checkpoints CASCADE"));
}

#[test]
fn frontier_confirmed_evidence_has_closed_resolution_authority() {
    assert!(INITIAL_UP.contains("CREATE TABLE public.federation_frontier_confirmed_evidence"));
    // `federation.md` §4.5.3 leaves current-v1 with exactly one clearing
    // authority: an accepted ak.fork.resolution. There is no historical-range
    // attestation branch and no same-scope witness re-agreement branch, so the
    // column enum is a single value rather than an open list.
    assert!(INITIAL_UP.contains(
        "local_resolution_kind text CHECK (local_resolution_kind IN ('fork_resolution_event'))"
    ));
    assert!(
        INITIAL_UP.contains(
            "CHECK ((local_resolution_kind IS NULL) = (local_resolution_digest IS NULL))"
        )
    );
    assert!(
        INITIAL_UP.contains("CHECK ((peer_alignment_digest IS NULL) = (peer_aligned_at IS NULL))")
    );
    assert!(
        INITIAL_DOWN
            .contains("DROP TABLE IF EXISTS federation_frontier_confirmed_evidence CASCADE")
    );
}

#[test]
fn franking_replay_nonce_ledger_has_bounded_expiry_contract() {
    assert!(INITIAL_UP.contains("CREATE TABLE public.moderation_franking_replay_nonces"));
    assert!(INITIAL_UP.contains("expires_at timestamp with time zone NOT NULL"));
    assert!(INITIAL_UP.contains("moderation_franking_replay_nonces_expiry_check"));
    assert!(INITIAL_UP.contains("moderation_franking_replay_nonces_expiry_idx"));
    assert!(
        INITIAL_DOWN.contains("DROP TABLE IF EXISTS moderation_franking_replay_nonces CASCADE")
    );
}

/// A collision verdict is not only a subtraction: it admits a winner.
///
/// `event-auth-state-resolution.md` section 6.3.3 point 3 makes the admitted
/// Event's local receipt timestamp the covering Seal's `sealed_at`, so the
/// verdict row has to carry that timestamp, and it has to be present exactly
/// when there is a winner to admit. Without the CHECK, a `canonical_winner`
/// verdict could persist with nothing to admit it under, and the admission
/// would silently fall back to a local clock — which is what makes two
/// Stations diverge.
#[test]
fn fork_normalization_carries_the_timestamp_its_winner_is_admitted_under() {
    assert!(INITIAL_UP.contains("CREATE TABLE public.federation_fork_normalization"));
    assert!(INITIAL_UP.contains("winner_sealed_at bigint"));
    assert!(INITIAL_UP.contains("CONSTRAINT federation_fork_normalization_winner_sealed_at_check"));
    assert!(INITIAL_UP.contains("(winner_canonical_bytes IS NULL) = (winner_sealed_at IS NULL)"));
    assert!(INITIAL_DOWN.contains("DROP TABLE IF EXISTS federation_fork_normalization"));
}

/// A directed Invite's live slot is the typed current target register. The
/// third-party commitment index is rebuildable from accepted create Events;
/// neither needs the retired `realm_invites` table or its status predicate.
#[test]
fn invite_current_registers_replace_the_retired_invite_table() {
    assert!(INITIAL_UP.contains("CREATE TABLE invite_lifecycle_current_results"));
    assert!(INITIAL_UP.contains("CREATE TABLE invite_live_target_current_results"));
    assert!(INITIAL_UP.contains("PRIMARY KEY(realm_id,invitee_account_id)"));
    assert!(INITIAL_UP.contains("CREATE TABLE invite_directed_invitee_current_results"));
    assert!(INITIAL_UP.contains("CREATE TABLE invite_third_party_create_index"));
    assert!(INITIAL_UP.contains("token_commitment TEXT COLLATE \"C\" NOT NULL UNIQUE"));
    assert!(INITIAL_DOWN.contains("DROP TABLE IF EXISTS invite_third_party_create_index"));
    assert!(
        !INITIAL_UP.contains("CREATE TABLE public.realm_invites"),
        "retired realm_invites must not return to the initial schema"
    );
}

#[test]
fn canonical_event_surfaces_use_the_committed_terminal_state() {
    assert!(INITIAL_UP.contains("CHECK (state IN ('queued', 'committed', 'rejected'))"));
    assert!(INITIAL_UP.contains("WHERE event.state = 'committed'"));
    assert!(INITIAL_UP.contains("CREATE VIEW public.committed_events AS"));
    assert!(!INITIAL_UP.contains("CREATE VIEW public.accepted_events AS"));
    assert!(INITIAL_UP.contains("WHERE state = 'committed';"));
    assert!(
        INITIAL_UP.contains("WHERE (kind = 'ak.realm.create'::text AND state = 'committed'::text)")
    );
    assert!(INITIAL_UP.contains("CREATE TRIGGER canonical_events_immutable"));
    assert!(INITIAL_UP.contains("BEFORE UPDATE ON public.canonical_events"));
    for immutable_column in [
        "OLD.id",
        "OLD.digest_suite",
        "OLD.digest",
        "OLD.actor_id",
        "OLD.actor_seq",
        "OLD.realm_id",
        "OLD.realm_pk",
        "OLD.scope_ref",
        "OLD.kind",
        "OLD.schema_id",
        "OLD.canonical_bytes",
        "OLD.envelope",
        "OLD.received_at",
        "OLD.committed_at",
        "OLD.rejection_reason",
    ] {
        assert!(
            INITIAL_UP.contains(immutable_column),
            "canonical Event immutability trigger omitted {immutable_column}"
        );
    }

    for stale in [
        "WHERE event.state = 'accepted'",
        "WHERE state = 'accepted' AND kind = 'ak.moderation.franking_proof'",
        "kind = 'ak.realm.create'::text AND state = 'accepted'::text",
        "OLD.kind='ak.account_data.set' AND OLD.state='accepted'",
        "visible := NEW.state='accepted'",
    ] {
        assert!(
            !INITIAL_UP.contains(stale),
            "canonical Event surface retained stale state predicate: {stale}"
        );
    }
}

#[test]
fn security_transaction_uses_the_protocol_terminal_outcome_name_at_creation() {
    assert!(INITIAL_UP.contains("terminal_outcome jsonb"));
    assert!(!INITIAL_UP.contains("terminal_result"));
}

#[test]
fn security_rotation_persists_its_authorizing_device_at_creation() {
    let security_transactions = INITIAL_UP
        .split("CREATE TABLE public.security_transactions (")
        .nth(1)
        .and_then(|tail| tail.split(");").next())
        .expect("security_transactions table");
    assert!(security_transactions.contains("authorizing_device_id text"));
    assert!(security_transactions.contains("kind = 'recovery' AND authorizing_device_id IS NULL"));
    assert!(
        security_transactions
            .contains("kind = 'security_rotation' AND authorizing_device_id IS NOT NULL")
    );

    let revocation_heads = INITIAL_UP
        .split("CREATE TABLE public.device_revocation_linearization_heads (")
        .nth(1)
        .and_then(|tail| tail.split(");").next())
        .expect("device_revocation_linearization_heads table");
    assert!(!revocation_heads.contains("authorizing_device_id"));
}

#[test]
fn recovery_policy_uses_the_protocol_acceptance_basis_name_at_creation() {
    assert!(INITIAL_UP.contains("acceptance_basis jsonb NOT NULL"));
    assert!(!INITIAL_UP.contains("acceptance_ref jsonb"));
}

#[test]
fn actor_private_ledger_admits_only_the_six_actor_private_kinds() {
    assert!(INITIAL_UP.contains(
        "kind IN ('ak.account_data.set', 'ak.agent.action_reject', 'ak.agent.action_request',\n            'ak.agent.draft.propose', 'ak.device.push_route', 'ak.read_cursor.advance')"
    ));
    assert!(!INITIAL_UP.contains("'ak.account.blocklist'"));
    assert!(INITIAL_UP.contains("WHERE e.kind='ak.account_data.set'"));
    // A ledger source is immutable, so no withdrawal can invalidate it.
    assert!(!INITIAL_UP.contains("invalidate_account_global_event"));
    assert!(INITIAL_UP.contains("CREATE TRIGGER immutable_actor_private_events"));
}
