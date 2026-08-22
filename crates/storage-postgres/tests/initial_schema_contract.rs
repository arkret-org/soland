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
