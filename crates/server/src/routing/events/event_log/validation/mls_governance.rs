use super::super::*;

pub(crate) async fn projected_media_plaintext_service_present(
    state: &AppState,
    realm_id: &str,
    payload: &Value,
) -> bool {
    payload_declares_media_plaintext_service(payload, &state.service_id)
        || realm_allows_plaintext_service_for_data_class(
            state,
            realm_id,
            arkret_core::PlaintextDataClassKind::MediaPlaintext,
        )
        .await
}

pub(crate) fn payload_declares_media_plaintext_service(payload: &Value, service_id: &str) -> bool {
    payload
        .pointer("/plaintext_visible_services")
        .and_then(Value::as_array)
        .is_some_and(|services| {
            services.iter().any(|service| {
                let Some(object) = service.as_object() else {
                    return false;
                };
                object.get("service_id").and_then(Value::as_str) == Some(service_id)
                    && object
                        .get("data_classes")
                        .and_then(Value::as_array)
                        .is_some_and(|classes| {
                            classes
                                .iter()
                                .any(|class| class.as_str() == Some("media_plaintext"))
                        })
            })
        })
}

pub(crate) fn projected_mls_governance_binding_covers_policy_root(
    state: &AppState,
    realm_id: &str,
    payload: &Value,
) -> bool {
    let expected_policy_root = payload_mls_governance_policy_root(payload);
    let projection = state.projection.lock();
    let mut observed_realm_mls_cell = false;
    for (cell, cell_state) in &projection.cells {
        let cell_id = cell.as_str();
        let is_mls_cell = cell_id.contains("ak.component.mls.epoch.v1")
            || cell_id.contains("ak.component.mls_epoch.v1")
            || cell_id.contains("ak.component.covered_seals.v1");
        if !is_mls_cell {
            continue;
        }
        let arkret_state::lattice::CellState::Value(value) = cell_state else {
            continue;
        };
        if !value_targets_realm(value, realm_id) {
            continue;
        }
        observed_realm_mls_cell = true;
        if mls_governance_value_covers_policy_root(value, expected_policy_root) {
            return true;
        }
    }
    !observed_realm_mls_cell && expected_policy_root.is_some()
}

/// SEC-03 — project the `discussion_metadata_digest` the realm's current MLS
/// epoch governance binding covers, so [`realm_policy_components_check`] can
/// recompute the `media_service_decrypts` fact and reject a stale / forged
/// binding (`media-service-binding.md` §8.2 rule 5). Mirrors the cell-selection
/// logic of [`projected_mls_governance_binding_covers_policy_root`]; returns the
/// digest from the first realm-targeting MLS cell that carries one, or `None`
/// when no projected binding advertises a digest (in which case the digest gate
/// is skipped and only policy_root coverage applies).
pub(super) fn projected_mls_governance_binding_metadata_digest(
    state: &AppState,
    realm_id: &str,
) -> Option<String> {
    let projection = state.projection.lock();
    for (cell, cell_state) in &projection.cells {
        let cell_id = cell.as_str();
        let is_mls_cell = cell_id.contains("ak.component.mls.epoch.v1")
            || cell_id.contains("ak.component.mls_epoch.v1")
            || cell_id.contains("ak.component.covered_seals.v1");
        if !is_mls_cell {
            continue;
        }
        let arkret_state::lattice::CellState::Value(value) = cell_state else {
            continue;
        };
        if !value_targets_realm(value, realm_id) {
            continue;
        }
        if let Some(digest) = mls_governance_value_discussion_metadata_digest(value) {
            return Some(digest.to_owned());
        }
    }
    None
}

/// SEC-03 — read the `discussion_metadata_digest` from a projected MLS cell
/// value, checking the same binding sub-objects that
/// [`mls_governance_value_covers_policy_root`] inspects for `policy_root`.
fn mls_governance_value_discussion_metadata_digest(value: &Value) -> Option<&str> {
    [
        value.pointer("/governance_binding/discussion_metadata_digest"),
        value.pointer("/mls_governance_binding/discussion_metadata_digest"),
        value.pointer("/discussion_metadata_digest"),
    ]
    .into_iter()
    .flatten()
    .find_map(|candidate| {
        candidate
            .as_str()
            .filter(|digest| !digest.trim().is_empty())
    })
}

fn payload_mls_governance_policy_root(payload: &Value) -> Option<&str> {
    payload
        .pointer("/mls_governance_binding/policy_root")
        .or_else(|| payload.pointer("/governance_binding/policy_root"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

fn value_targets_realm(value: &Value, realm_id: &str) -> bool {
    if value.get("space_id").is_some() {
        return false;
    }
    value
        .get("realm_id")
        .and_then(Value::as_str)
        .is_none_or(|value| value == realm_id)
}

fn mls_governance_value_covers_policy_root(
    value: &Value,
    expected_policy_root: Option<&str>,
) -> bool {
    let candidates = [
        value.pointer("/governance_binding/policy_root"),
        value.pointer("/mls_governance_binding/policy_root"),
        value.pointer("/policy_root"),
    ];
    candidates.iter().flatten().any(|candidate| {
        candidate.as_str().is_some_and(|policy_root| {
            !policy_root.trim().is_empty()
                && expected_policy_root.is_none_or(|expected| expected == policy_root)
        })
    })
}
