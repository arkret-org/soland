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
fn applet_identity_winner_is_independent_from_exact_scope_installations() {
    assert!(INITIAL_UP.contains("CREATE TABLE public.applet_managed_identities"));
    assert!(INITIAL_UP.contains("PRIMARY KEY (applet_id, target_principal_server_id)"));
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
fn franking_replay_nonce_ledger_has_bounded_expiry_contract() {
    assert!(INITIAL_UP.contains("CREATE TABLE public.moderation_franking_replay_nonces"));
    assert!(INITIAL_UP.contains("expires_at timestamp with time zone NOT NULL"));
    assert!(INITIAL_UP.contains("moderation_franking_replay_nonces_expiry_check"));
    assert!(INITIAL_UP.contains("moderation_franking_replay_nonces_expiry_idx"));
    assert!(
        INITIAL_DOWN.contains("DROP TABLE IF EXISTS moderation_franking_replay_nonces CASCADE")
    );
}
