use super::*;

#[test]
fn pattern_matches_concrete_path() {
    assert!(pattern_matches_path(
        "/_arkret/self/events",
        "/_arkret/self/events"
    ));
    assert!(!pattern_matches_path(
        "/_arkret/self/events",
        "/_arkret/self/other"
    ));
}

#[test]
fn pattern_matches_param_segment() {
    assert!(pattern_matches_path(
        "/_soland/self/spaces/{space_id}",
        "/_soland/self/spaces/ak:space:01"
    ));
    // Different segment count → no match.
    assert!(!pattern_matches_path(
        "/_soland/self/spaces/{space_id}",
        "/_soland/self/spaces/ak:space:01/policy"
    ));
    // Param must be non-empty.
    assert!(!pattern_matches_path(
        "/_soland/self/spaces/{space_id}",
        "/_soland/self/spaces/"
    ));
}

#[test]
fn pattern_matches_multi_param_segments() {
    assert!(pattern_matches_path(
        "/_arkret/self/events/{event_id}/refs/{ref_id}",
        "/_arkret/self/events/ak:event:01/refs/ak:event:02"
    ));
}

#[test]
fn pattern_rejects_segment_mismatch() {
    assert!(!pattern_matches_path("/_arkret/self/events", "/_arkret"));
    assert!(!pattern_matches_path("/_arkret", "/_arkret/self/events"));
}

#[test]
fn openapi_32_query_method_is_preserved_for_allow_headers() {
    assert_eq!(method_name_to_method("query"), Some(Method::QUERY));
}

#[test]
fn known_routes_map_resolves_known_path() {
    // Seed the known-routes table with the protocol surface we'd
    // expect the catch-all to disambiguate against. We don't go
    // through the full OpenAPI doc build path because that pulls in
    // the entire service router; the helper logic under test is
    // pattern-matching, not OpenAPI introspection.
    let _ = KNOWN_ROUTES.set(vec![
        (
            "/_arkret/self/events".to_owned(),
            vec![Method::GET, Method::POST],
        ),
        (
            "/_soland/self/spaces/{space_id}".to_owned(),
            vec![Method::GET],
        ),
    ]);

    // Known path → returns the canonical method set (in
    // `METHOD_HEADER_ORDER`) so the `Allow` header is stable.
    let methods = allow_methods_for_path("/_arkret/self/events")
        .expect("/_arkret/self/events is registered with at least one method");
    assert_eq!(methods, vec![Method::GET, Method::POST]);

    let methods = allow_methods_for_path("/_soland/self/spaces/ak:space:abc")
        .expect("/_soland/self/spaces/{id} resolves with a concrete id");
    assert_eq!(methods, vec![Method::GET]);

    // Unknown path → `None`, which is the cue for `api_not_found`
    // to emit `unrecognized_endpoint` instead of `method_not_allowed`.
    assert!(allow_methods_for_path("/_arkret/self/does-not-exist").is_none());
    assert!(allow_methods_for_path("/_soland/peer/does-not-exist").is_none());
}
