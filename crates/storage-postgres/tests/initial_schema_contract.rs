const INITIAL_UP: &str = include_str!("../migrations/00000000000000_initial/up.sql");
const INITIAL_DOWN: &str = include_str!("../migrations/00000000000000_initial/down.sql");

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
    assert!(INITIAL_UP.contains("'bot_actor_id'"));
    assert!(INITIAL_UP.contains("'globally_fenced_at'"));
    assert!(INITIAL_DOWN.contains("DROP TABLE IF EXISTS applet_managed_identities CASCADE"));
}

#[test]
fn seal_data_event_manifest_is_created_and_dropped_symmetrically() {
    assert!(INITIAL_UP.contains("CREATE TABLE public.state_seal_data_event_manifests"));
    assert!(INITIAL_UP.contains("leaf_digests text[] NOT NULL"));
    assert!(INITIAL_UP.contains("state_seal_data_event_manifests_immutable"));
    assert!(INITIAL_DOWN.contains("DROP TABLE IF EXISTS state_seal_data_event_manifests CASCADE"));
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

/// The direct-invite read model's live set is the one §5.3 defines.
///
/// `governance-objects.md` §5.3: "直接邀请的 live 集合是 `{pending, send_failed}`。
/// `claimed` **不属于**该集合". The index carried `claimed` as a third state on
/// the strength of a comment that turned out to be wrong — a claimed 3PID
/// invite keeps a non-NULL `third_party_invite` (the claim projection nulls
/// members inside that JSONB object, never the column), so it is already
/// excluded by the second conjunct, and a direct invite cannot reach `claimed`
/// because the claim path matches on a token commitment inside
/// `third_party_invite`.
///
/// It was unreachable rather than wrong, which is exactly why it needs pinning:
/// nothing failed while it was there, and nothing would fail if it came back.
#[test]
fn direct_invite_live_uniqueness_covers_only_the_live_states() {
    assert!(INITIAL_UP.contains("CREATE UNIQUE INDEX realm_invites_live_direct_unique_idx"));
    assert!(INITIAL_UP.contains(
        "(status = ANY (ARRAY['pending'::text, 'send_failed'::text]))"
    ));
    assert!(
        !INITIAL_UP.contains(
            "(status = ANY (ARRAY['pending'::text, 'claimed'::text, 'send_failed'::text]))"
        ),
        "claimed is not in the direct-invite live set"
    );
}
