use super::*;
pub(super) use crate::canonical_value_digest;

pub(super) fn require_object_field(
    object: &serde_json::Map<String, Value>,
    key: &'static str,
) -> Result<(), EventValidationError> {
    match object.get(key) {
        Some(Value::Object(_)) => Ok(()),
        Some(_) => Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "event payload must be a JSON object",
        )),
        None => Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "missing_param",
            "event payload is required",
        )),
    }
}

pub(super) fn event_ref_list(
    object: &serde_json::Map<String, Value>,
    key: &str,
    max_len: usize,
) -> Result<Vec<String>, EventValidationError> {
    let Some(value) = object.get(key) else {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "missing_param",
            "event reference lists are required",
        ));
    };
    let Some(values) = value.as_array() else {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "event reference lists must be arrays",
        ));
    };
    // scalability-constraints.md section 2. `prev_refs` carries reason_code
    // `prev_refs_too_large` (which also covers the MUST-dedup rule); other ref
    // lists carry `refs_too_large`. Both are `schema_violation` reasons.
    let too_large_reason = if key == "prev_refs" {
        "prev_refs_too_large"
    } else {
        "refs_too_large"
    };
    let count_error = if key == "prev_refs" {
        arkret_sdk::validate_event_prev_ref_count(values.len()).is_err()
    } else {
        arkret_sdk::validate_event_ref_count(values.len()).is_err()
    };
    if values.len() > max_len || count_error {
        return Err(event_validation_error(
            StatusCode::BAD_REQUEST,
            too_large_reason,
            "event reference list exceeds the v1 maximum entry count",
        ));
    }
    let mut seen = std::collections::HashSet::with_capacity(values.len());
    values
        .iter()
        .map(|value| {
            let Some(event_id) = value.as_str() else {
                return Err(event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_param",
                    "event references must be strings",
                ));
            };
            if !is_valid_event_id(event_id) {
                return Err(event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_param",
                    "event references must use the ak:event: typed prefix",
                ));
            }
            // Entries MUST be deduplicated.
            if !seen.insert(event_id) {
                return Err(event_validation_error(
                    StatusCode::BAD_REQUEST,
                    too_large_reason,
                    "event reference list MUST NOT contain duplicate entries",
                ));
            }
            Ok(event_id.to_owned())
        })
        .collect()
}

#[cfg(test)]
mod prev_refs_limit_tests {
    use serde_json::json;

    use super::*;

    fn object(refs: serde_json::Value) -> serde_json::Map<String, Value> {
        json!({ "prev_refs": refs }).as_object().unwrap().clone()
    }

    #[test]
    fn prev_refs_over_max_rejected() {
        let refs: Vec<Value> = (0..(MAX_EVENT_PREV_REFS + 1))
            .map(|i| json!(format!("ak:event:e{i}")))
            .collect();
        let err =
            event_ref_list(&object(json!(refs)), "prev_refs", MAX_EVENT_PREV_REFS).unwrap_err();
        assert_eq!(err.code, "prev_refs_too_large");
    }

    #[test]
    fn duplicate_prev_refs_rejected() {
        let refs = json!(["ak:event:e1", "ak:event:e1"]);
        let err = event_ref_list(&object(refs), "prev_refs", MAX_EVENT_PREV_REFS).unwrap_err();
        assert_eq!(err.code, "prev_refs_too_large");
    }

    #[test]
    fn distinct_prev_refs_within_limit_ok() {
        let refs = json!(["ak:event:e1", "ak:event:e2"]);
        let out = event_ref_list(&object(refs), "prev_refs", MAX_EVENT_PREV_REFS).unwrap();
        assert_eq!(
            out,
            vec!["ak:event:e1".to_owned(), "ak:event:e2".to_owned()]
        );
    }
}
