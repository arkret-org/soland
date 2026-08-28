const INITIAL_UP: &str = include_str!("../migrations/00000000000000_initial/up.sql");
const INITIAL_DOWN: &str = include_str!("../migrations/00000000000000_initial/down.sql");
const AGENT_IDENTIFIER_CONSTRAINTS_UP: &str =
    include_str!("../migrations/20260828010000_agent_principal_identifier_constraints/up.sql");
const AGENT_WEBVH_BINDING_UP: &str =
    include_str!("../migrations/20260828020000_agent_principal_webvh_binding/up.sql");

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

    for migration in [INITIAL_UP, AGENT_WEBVH_BINDING_UP] {
        assert!(migration.contains(did_core_check));
        assert!(migration.contains(delegation_check));
        assert!(migration.contains(
            "id = 'ak:did_core:webvh:' || split_part(controller_authorization_ref, ':', 3)"
        ) || migration.contains(
            "id = ('ak:did_core:webvh:'::text || split_part(controller_authorization_ref, ':'::text, 3))"
        ));
        assert!(!migration.contains("controller_authorization_ref LIKE (id || '#%')"));
        assert!(!migration.contains("controller_authorization_ref ~~ (id || '#%'"));
    }

    assert!(
        AGENT_IDENTIFIER_CONSTRAINTS_UP
            .contains("cannot satisfy the Arkret did_core/full-DID contract")
    );
    assert!(AGENT_WEBVH_BINDING_UP.contains("does not project to the stored did_core id"));
}
