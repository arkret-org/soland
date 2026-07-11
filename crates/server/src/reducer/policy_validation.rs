//! Join / admission policy validation and encryption-floor helpers.
//!
//! Split out of the `reducer` mod file; re-exported there so the
//! `crate::reducer::validate_join_policy_payload` public path and the
//! sibling `apply_*` modules' `super::*` access stay unchanged.

use std::collections::BTreeSet;

use arkret_sdk::Operation;
use chrono::{DateTime, Duration, Utc};
use serde_json::Value;

pub(crate) const REALM_ENCRYPTION_PROFILE_CREATE_LOCKED: &str =
    "realm_encryption_profile_create_locked";
pub(crate) const CIRCLE_ENCRYPTION_PROFILE_CREATE_LOCKED: &str =
    "circle_encryption_profile_create_locked";
pub(crate) const CIRCLE_ENCRYPTION_BELOW_REALM_FLOOR: &str = "circle_encryption_below_realm_floor";
/// AKP-0007 §8 — pulling *another* actor into a Circle (none/left → active by
/// an actor other than the target) requires the requester to hold
/// `ak.circle.member.manage` (narrowed by `allowed_circle_ids`) on this Circle.
/// The HTTP surface runs the authoritative `SolandAuthzEngine::check` and stamps a
/// verdict into the operation payload; the reducer fails closed when that
/// verdict is absent or false, so an unauthorised one-way add is rejected even
/// if it bypasses the HTTP gate.
pub(crate) const CIRCLE_MEMBER_MANAGE_CAPABILITY_REQUIRED: &str =
    "circle_member_manage_capability_required";
/// AKP-0007 §8 — a self-service join (none/left → active *by the target actor*)
/// is only permitted on an `open` Circle. Self-joining a non-`open` Circle must
/// go through an invite/manage path.
pub(crate) const CIRCLE_JOIN_NOT_OPEN: &str = "circle_join_not_open";
/// One-way ratchet: effective `content_encryption_floor` MUST be monotonically
/// non-decreasing. Lowering `e2ee_required` back to `allow_plaintext` is rejected.
pub(crate) const CONTENT_ENCRYPTION_FLOOR_DOWNGRADE: &str = "content_encryption_floor_downgrade";
/// One-way ratchet: effective metadata encryption floor MUST be monotonically
/// non-decreasing (`allow_plaintext < e2ee_required`).
pub(crate) const METADATA_ENCRYPTION_FLOOR_DOWNGRADE: &str = "metadata_encryption_floor_downgrade";
/// One-way ratchet: effective Realm `content_scheme` MUST NOT downgrade from the
/// exporter-derived AEAD scheme (`mls-exporter-aead-v1`) back to the application
/// message scheme (`mls-rfc9420`). Lowering the negotiated scheme would let a
/// member re-key history content under a weaker mechanism after the realm has
/// committed to the exporter-AEAD history-sharing path.
pub(crate) const CONTENT_SCHEME_DOWNGRADE: &str = "content_scheme_downgrade";
/// realm-and-space.md §2.3.1 / encryption-and-audit.md §2.10.8 — a Realm Recovery
/// Key durability policy with `mode != none` is only meaningful on a
/// `content_scheme=mls-exporter-aead-v1` Realm, because `mls-rfc9420`
/// (PrivateMessage) has no deliverable `history_secret` to seal to recovery
/// recipients. Declaring `mode != none` on an incompatible Realm is rejected.
pub(crate) const DURABILITY_SCHEME_INCOMPATIBLE: &str = "durability_scheme_incompatible";
/// realm-and-space.md §2.3.1 — `durability_policy` invariants: `recovery_recipients`
/// MUST be non-empty when `mode != none`, and `threshold` (`1 <= k <= n ==
/// len(recovery_recipients)`) is required when `mode=threshold`.
pub(crate) const DURABILITY_POLICY_INVALID: &str = "durability_policy_invalid";

/// R1.2 — pure validation for a `ak.member.state{join,routable}`
/// `delivery_binding` against a projected
/// `ak.realm.delivery_binding_policy` payload. Returns `Ok(())` when the
/// binding is admissible; `Err(reason_code)` otherwise. Reason codes
/// mirror the spec join-policy.md §5.1 catalogue.
pub(crate) fn enforce_delivery_binding_policy(
    policy: &Value,
    binding: &serde_json::Map<String, Value>,
) -> Result<(), &'static str> {
    let binding_source = binding
        .get("binding_source")
        .and_then(Value::as_str)
        .unwrap_or("");
    let recipient_service_id = binding
        .get("recipient_service_id")
        .and_then(Value::as_str)
        .unwrap_or("");

    // `allow_binding_sources` is an explicit allow-list. Missing or
    // empty means "no source admissible" — fail closed.
    let allow_sources: Vec<&str> = policy
        .get("allow_binding_sources")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if !allow_sources.contains(&binding_source) {
        return Err("binding_source_not_allowed");
    }
    // `did_document_default` requires the toggle even if the source list
    // includes it (spec §5.1.3 — organization/compliance Realms must set
    // `allow_did_document_default=false`).
    if binding_source == "did_document_default"
        && !policy
            .get("allow_did_document_default")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    {
        return Err("binding_source_not_allowed");
    }

    // `allowed_recipient_services` is fail-closed (member-delivery-binding.md
    // §2 / §4, event-payload.schema.json delivery_binding_policy_payload):
    // empty array `[]` — and an omitted field, which defaults to `[]` —
    // rejects every recipient service; only the explicit sentinel `["*"]`
    // means unrestricted. An empty list MUST NOT be read as "unrestricted".
    let allowed_recipients: Vec<&str> = policy
        .get("allowed_recipient_services")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let unrestricted_sentinel = allowed_recipients == ["*"];
    if !unrestricted_sentinel && !allowed_recipients.contains(&recipient_service_id) {
        return Err("recipient_service_not_allowed");
    }

    // `binding_source=explicit` requires a signed `service_acceptance_ref`.
    if binding_source == "explicit"
        && !binding
            .get("service_acceptance_ref")
            .map(|v| v.is_string())
            .unwrap_or(false)
    {
        return Err("service_acceptance_missing");
    }

    // Frontier check: if the policy declares `policy_frontier`, the
    // binding's carried `delivery_binding_frontier` MUST match or
    // exceed it lexicographically. Missing carried frontier = stale.
    if let Some(policy_frontier) = policy.get("policy_frontier").and_then(Value::as_str) {
        let carried = binding
            .get("delivery_binding_frontier")
            .and_then(Value::as_str);
        match carried {
            None => return Err("delivery_binding_stale"),
            Some(c) if c < policy_frontier => return Err("delivery_binding_stale"),
            _ => {}
        }
    }
    Ok(())
}

pub(crate) fn state_payload_value(payload: &Value) -> &Value {
    payload.get("value").unwrap_or(payload)
}

const SEARCH_POLICY_PROFILES: &[&str] = &[
    "ak.profile.search.client_index.v1",
    "ak.profile.search.blind_index.v1",
    "ak.profile.search.forward_private.v1",
];
const SEARCH_POLICY_DATA_CLASSES: &[&str] = &[
    "encrypted_index",
    "blind_tokens",
    "plaintext",
    "reversible_summary",
];
const SEARCH_POLICY_LEAKAGE_CLASSES: &[&str] =
    &["deterministic_token", "forward_private", "access_hiding"];
const SEARCH_POLICY_REVOCATION_BEHAVIORS: &[&str] = &["fail_closed", "drop_stale"];

fn required_string_array(
    policy: &Value,
    field: &'static str,
    allowed: Option<&[&str]>,
    invalid_reason: &'static str,
) -> Result<Vec<String>, &'static str> {
    let Some(items) = policy.get(field).and_then(Value::as_array) else {
        return Err(invalid_reason);
    };
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let Some(value) = item.as_str().filter(|value| !value.trim().is_empty()) else {
            return Err(invalid_reason);
        };
        if let Some(allowed) = allowed
            && !allowed.contains(&value)
        {
            return Err(invalid_reason);
        }
        if !seen.insert(value.to_owned()) {
            return Err(invalid_reason);
        }
        out.push(value.to_owned());
    }
    Ok(out)
}

pub(crate) fn validate_realm_search_policy_payload(policy: &Value) -> Result<(), &'static str> {
    let Some(object) = policy.as_object() else {
        return Err("search_policy_invalid");
    };
    let profiles = required_string_array(
        policy,
        "enabled_profile_refs",
        Some(SEARCH_POLICY_PROFILES),
        "search_policy_enabled_profile_refs_invalid",
    )?;
    required_string_array(
        policy,
        "allowed_service_ids",
        None,
        "search_policy_allowed_service_ids_invalid",
    )?;
    let data_classes = required_string_array(
        policy,
        "data_classes",
        Some(SEARCH_POLICY_DATA_CLASSES),
        "search_policy_data_class_invalid",
    )?;
    if data_classes.is_empty() {
        return Err("search_policy_data_classes_empty");
    }
    let revocation_behavior = object
        .get("revocation_behavior")
        .and_then(Value::as_str)
        .ok_or("search_policy_revocation_behavior_missing")?;
    if !SEARCH_POLICY_REVOCATION_BEHAVIORS.contains(&revocation_behavior) {
        return Err("search_policy_revocation_behavior_invalid");
    }
    let leakage_class = object
        .get("leakage_class")
        .and_then(Value::as_str)
        .unwrap_or("deterministic_token");
    if !SEARCH_POLICY_LEAKAGE_CLASSES.contains(&leakage_class) {
        return Err("search_policy_leakage_class_invalid");
    }
    if leakage_class == "access_hiding" {
        return Err("search_policy_access_hiding_unsupported");
    }
    let forward_private_enabled = profiles
        .iter()
        .any(|profile| profile == "ak.profile.search.forward_private.v1");
    if forward_private_enabled && leakage_class != "forward_private" {
        return Err("search_policy_forward_private_leakage_class_required");
    }
    if leakage_class == "forward_private" && !forward_private_enabled {
        return Err("search_policy_forward_private_profile_required");
    }
    if forward_private_enabled
        && !profiles
            .iter()
            .any(|profile| profile == "ak.profile.search.blind_index.v1")
    {
        return Err("search_policy_forward_private_blind_index_required");
    }
    if let Some(value) = object.get("token_rotation_cadence_ms")
        && value.as_u64().is_none()
    {
        return Err("search_policy_token_rotation_cadence_invalid");
    }
    if forward_private_enabled && object.get("token_rotation_cadence_ms").is_none() {
        return Err("search_policy_forward_private_token_rotation_required");
    }
    if let Some(value) = object.get("index_retention_ms")
        && value.as_u64().is_none()
    {
        return Err("search_policy_index_retention_invalid");
    }
    Ok(())
}

const JOIN_POLICY_GATE_KINDS: &[&str] = &[
    "claim_required",
    "application_form",
    "challenge_response",
    "manual_review",
    "parent_membership",
    "principal_admission",
    "cooldown",
];

const CHALLENGE_KINDS: &[&str] = &["captcha", "pow", "attested_human", "idp_oidc"];

/// Validate the Join Policy subset that the reducer must enforce before
/// accepting the policy-components cell.
pub fn validate_join_policy_payload(join_policy: &Value) -> Result<(), &'static str> {
    let Some(object) = join_policy.as_object() else {
        return Err("join_policy must be an object");
    };
    match object.get("combinator").and_then(Value::as_str) {
        Some("all" | "any") => {}
        Some(_) => return Err("join_policy_combinator_invalid"),
        None => return Err("join_policy_combinator_missing"),
    }
    let Some(gates) = object.get("gates").and_then(Value::as_array) else {
        return Err("join_policy requires gates");
    };
    if gates.is_empty() {
        return Err("join_policy requires at least one gate");
    }
    if gates.len() > 16 {
        return Err("join_policy_too_many_gates");
    }
    let mut seen_gate_ids = BTreeSet::new();
    let mut review_capability_required = false;
    for gate in gates {
        let Some(gate) = gate.as_object() else {
            return Err("join_policy gates must be objects");
        };
        let Some(gate_id) = gate.get("gate_id").and_then(Value::as_str) else {
            return Err("join_policy gate requires gate_id");
        };
        if gate_id.is_empty() || !seen_gate_ids.insert(gate_id.to_owned()) {
            return Err("join_policy_duplicate_gate_id");
        }
        let Some(kind) = gate.get("kind").and_then(Value::as_str) else {
            return Err("join_policy_gate_kind_invalid");
        };
        if !JOIN_POLICY_GATE_KINDS.contains(&kind) {
            return Err("join_policy_gate_kind_invalid");
        }
        match kind {
            "principal_admission" => validate_principal_admission_gate(gate)?,
            "parent_membership" => validate_parent_membership_gate(gate)?,
            "challenge_response" => validate_challenge_response_gate(gate)?,
            "cooldown" => validate_cooldown_gate(gate)?,
            "claim_required" => validate_claim_required_gate(gate)?,
            "application_form" => {
                review_capability_required = true;
                validate_application_form_gate(gate)?;
            }
            "manual_review" => {
                review_capability_required = true;
                validate_auto_resolve(gate, false)?;
            }
            _ => unreachable!("gate kind checked above"),
        }
    }
    if review_capability_required
        && object
            .get("review_capability")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .is_none()
    {
        return Err("join_policy_review_capability_required");
    }
    validate_reviewer_quorum(join_policy)?;
    Ok(())
}

fn validate_auto_resolve(
    gate: &serde_json::Map<String, Value>,
    expected: bool,
) -> Result<(), &'static str> {
    if let Some(value) = gate.get("auto_resolve")
        && value.as_bool() != Some(expected)
    {
        return Err("join_policy_gate_auto_resolve_invalid");
    }
    Ok(())
}

pub(crate) fn validate_principal_admission_gate(
    gate: &serde_json::Map<String, Value>,
) -> Result<(), &'static str> {
    validate_auto_resolve(gate, true)?;
    let has_allowed_methods = validate_did_method_list(gate, "allowed_did_methods")?;
    let has_allowed_dids = validate_did_list(gate, "allowed_principal_dids")?;
    let has_denied_dids = validate_did_list(gate, "denied_principal_dids")?;
    if !(has_allowed_methods || has_allowed_dids || has_denied_dids) {
        return Err("principal_admission_requires_selector");
    }
    Ok(())
}

pub(crate) fn validate_parent_membership_gate(
    gate: &serde_json::Map<String, Value>,
) -> Result<(), &'static str> {
    validate_auto_resolve(gate, true)?;
    let Some(source_realms) = gate
        .get("membership_source_realm_ids")
        .and_then(Value::as_array)
    else {
        return Err("parent_membership_sources_invalid");
    };
    if source_realms.is_empty() {
        return Err("parent_membership_sources_invalid");
    }
    let mut seen = BTreeSet::new();
    for source in source_realms {
        let Some(source) = source.as_str().filter(|value| !value.trim().is_empty()) else {
            return Err("parent_membership_sources_invalid");
        };
        if arkret_sdk::RealmId::new(source.to_owned()).is_err() {
            return Err("parent_membership_sources_invalid");
        }
        if !seen.insert(source.to_owned()) {
            return Err("parent_membership_sources_invalid");
        }
    }
    match gate.get("require_min_membership").and_then(Value::as_str) {
        Some("invite" | "join") => Ok(()),
        _ => Err("parent_membership_min_membership_invalid"),
    }
}

pub(crate) fn validate_challenge_response_gate(
    gate: &serde_json::Map<String, Value>,
) -> Result<(), &'static str> {
    validate_auto_resolve(gate, true)?;
    let Some(provider_did) = gate.get("provider_did").and_then(Value::as_str) else {
        return Err("challenge_response_provider_invalid");
    };
    if arkret_sdk::Did::new(provider_did.to_owned()).is_err() {
        return Err("challenge_response_provider_invalid");
    }
    let Some(kinds) = gate.get("challenge_kinds").and_then(Value::as_array) else {
        return Err("challenge_response_kinds_invalid");
    };
    if kinds.is_empty() {
        return Err("challenge_response_kinds_invalid");
    }
    let mut seen = BTreeSet::new();
    for kind in kinds {
        let Some(kind) = kind.as_str() else {
            return Err("challenge_response_kinds_invalid");
        };
        if !CHALLENGE_KINDS.contains(&kind) || !seen.insert(kind.to_owned()) {
            return Err("challenge_response_kinds_invalid");
        }
    }
    let Some(max_age) = gate.get("max_proof_age").and_then(Value::as_str) else {
        return Err("challenge_response_max_proof_age_invalid");
    };
    parse_iso8601_duration(max_age)
        .filter(|duration| *duration > Duration::zero())
        .ok_or("challenge_response_max_proof_age_invalid")?;
    Ok(())
}

pub(crate) fn validate_cooldown_gate(
    gate: &serde_json::Map<String, Value>,
) -> Result<(), &'static str> {
    validate_auto_resolve(gate, true)?;
    let Some(min_interval) = gate.get("min_interval_since_leave").and_then(Value::as_str) else {
        return Err("cooldown_min_interval_invalid");
    };
    parse_iso8601_duration(min_interval)
        .filter(|duration| *duration > Duration::zero())
        .ok_or("cooldown_min_interval_invalid")?;
    Ok(())
}

pub(crate) fn validate_claim_required_gate(
    gate: &serde_json::Map<String, Value>,
) -> Result<(), &'static str> {
    validate_auto_resolve(gate, true)?;
    let Some(claims) = gate.get("requires_claims").and_then(Value::as_array) else {
        return Err("claim_required_claims_invalid");
    };
    if claims.is_empty() {
        return Err("claim_required_claims_invalid");
    }
    Ok(())
}

pub(crate) fn validate_application_form_gate(
    gate: &serde_json::Map<String, Value>,
) -> Result<(), &'static str> {
    validate_auto_resolve(gate, false)?;
    let Some(questions) = gate.get("questions").and_then(Value::as_array) else {
        return Err("application_form_questions_invalid");
    };
    if questions.is_empty() || questions.len() > 64 {
        return Err("application_form_questions_invalid");
    }
    Ok(())
}

fn validate_reviewer_quorum(join_policy: &Value) -> Result<(), &'static str> {
    let Some(quorum) = join_policy.get("reviewer_quorum") else {
        return Ok(());
    };
    if let Some(value) = quorum.as_str() {
        return match value {
            "any" | "majority" | "all" => Ok(()),
            _ => Err("join_policy_reviewer_quorum_invalid"),
        };
    }
    let Some(object) = quorum.as_object() else {
        return Err("join_policy_reviewer_quorum_invalid");
    };
    let Some(threshold) = object.get("threshold").and_then(Value::as_u64) else {
        return Err("join_policy_reviewer_quorum_invalid");
    };
    if threshold == 0 {
        return Err("join_policy_reviewer_quorum_invalid");
    }
    let Some(reviewers) = object.get("reviewers").and_then(Value::as_array) else {
        return Err("join_policy_reviewer_quorum_invalid");
    };
    let mut unique_reviewers = BTreeSet::new();
    for reviewer in reviewers {
        let Some(reviewer) = reviewer.as_str() else {
            return Err("join_policy_reviewer_quorum_invalid");
        };
        if arkret_sdk::Did::new(reviewer.to_owned()).is_err() {
            return Err("join_policy_reviewer_quorum_invalid");
        }
        unique_reviewers.insert(reviewer.to_owned());
    }
    if threshold as usize > unique_reviewers.len() {
        return Err("join_policy_reviewer_quorum_invalid");
    }
    Ok(())
}

pub(crate) fn validate_did_method_list(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<bool, &'static str> {
    let Some(value) = object.get(field) else {
        return Ok(false);
    };
    let Some(values) = value.as_array() else {
        return Err("principal_admission_methods_invalid");
    };
    for value in values {
        let Some(method) = value.as_str() else {
            return Err("principal_admission_methods_invalid");
        };
        if normalize_policy_did_method(method).is_none() {
            return Err("principal_admission_methods_invalid");
        }
    }
    Ok(!values.is_empty())
}

pub(crate) fn validate_did_list(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<bool, &'static str> {
    let Some(value) = object.get(field) else {
        return Ok(false);
    };
    let Some(values) = value.as_array() else {
        return Err("principal_admission_dids_invalid");
    };
    for value in values {
        let Some(did) = value.as_str() else {
            return Err("principal_admission_dids_invalid");
        };
        if arkret_sdk::Did::new(did.to_owned()).is_err() {
            return Err("principal_admission_dids_invalid");
        }
    }
    Ok(!values.is_empty())
}

pub(crate) fn normalize_policy_did_method(value: &str) -> Option<&str> {
    let method = value.strip_prefix("did:")?;
    (!method.is_empty()
        && method
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()))
    .then_some(method)
}

pub(crate) fn principal_admission_gate_allows(
    gate: &serde_json::Map<String, Value>,
    member: &str,
) -> bool {
    if !principal_admission_gate_has_selector(gate) {
        return false;
    }
    let Ok(member_did) = arkret_sdk::Did::new(member.to_owned()) else {
        return false;
    };
    if did_list_contains(gate, "denied_principal_dids", member) {
        return false;
    }
    if did_list_non_empty(gate, "allowed_principal_dids")
        && !did_list_contains(gate, "allowed_principal_dids", member)
    {
        return false;
    }
    let method = member_did.method();
    if let Some(methods) = gate.get("allowed_did_methods").and_then(Value::as_array)
        && !methods.is_empty()
        && !methods.iter().any(|value| {
            value
                .as_str()
                .and_then(normalize_policy_did_method)
                .is_some_and(|allowed| allowed == method)
        })
    {
        return false;
    }
    true
}

pub(crate) fn principal_admission_gate_has_selector(gate: &serde_json::Map<String, Value>) -> bool {
    did_list_non_empty(gate, "allowed_principal_dids")
        || did_list_non_empty(gate, "denied_principal_dids")
        || gate
            .get("allowed_did_methods")
            .and_then(Value::as_array)
            .is_some_and(|values| !values.is_empty())
}

pub(crate) fn did_list_non_empty(gate: &serde_json::Map<String, Value>, field: &str) -> bool {
    gate.get(field)
        .and_then(Value::as_array)
        .is_some_and(|values| !values.is_empty())
}

pub(crate) fn did_list_contains(
    gate: &serde_json::Map<String, Value>,
    field: &str,
    did: &str,
) -> bool {
    gate.get(field)
        .and_then(Value::as_array)
        .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(did)))
}

pub(crate) fn membership_state_satisfies_minimum(state: &str, required: &str) -> bool {
    match required {
        "join" => state == "join",
        "invite" => matches!(state, "invite" | "join"),
        _ => false,
    }
}

pub(crate) fn claim_required_gate_has_proof(
    gate: &serde_json::Map<String, Value>,
    proof: &serde_json::Map<String, Value>,
) -> bool {
    let required_claims = gate
        .get("requires_claims")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|claim| !claim.trim().is_empty())
        .collect::<Vec<_>>();
    if required_claims.is_empty() {
        return false;
    }
    let Some(presentation) = proof.get("claim_presentation") else {
        return false;
    };
    claim_presentation_present(presentation)
        && required_claims
            .iter()
            .all(|claim| claim_presentation_covers_claim(presentation, claim))
}

fn claim_presentation_present(value: &Value) -> bool {
    match value {
        Value::String(value) => !value.trim().is_empty(),
        Value::Object(object) => !object.is_empty(),
        Value::Array(values) => !values.is_empty(),
        _ => false,
    }
}

fn claim_presentation_covers_claim(value: &Value, claim: &str) -> bool {
    match value {
        Value::String(value) => !value.trim().is_empty(),
        Value::Array(values) => values
            .iter()
            .any(|value| claim_presentation_covers_claim(value, claim)),
        Value::Object(object) => {
            for field in ["claim", "claim_type", "type", "id", "name"] {
                if object.get(field).and_then(Value::as_str) == Some(claim) {
                    return true;
                }
            }
            match object.get("claims") {
                Some(Value::Object(claims)) if claims.contains_key(claim) => true,
                Some(value) => claim_presentation_covers_claim(value, claim),
                None => false,
            }
        }
        _ => false,
    }
}

pub(crate) fn challenge_response_gate_allows(
    gate: &serde_json::Map<String, Value>,
    proof: &serde_json::Map<String, Value>,
    now: DateTime<Utc>,
) -> bool {
    let Some(challenge_proof) = proof.get("challenge_proof").and_then(Value::as_object) else {
        return false;
    };
    if challenge_proof
        .get("challenge_id")
        .and_then(Value::as_str)
        .is_none_or(|value| value.trim().is_empty())
    {
        return false;
    }
    let provider_did = gate.get("provider_did").and_then(Value::as_str);
    if challenge_proof.get("issued_by").and_then(Value::as_str) != provider_did {
        return false;
    }
    if !challenge_kind_allowed(gate, challenge_proof) {
        return false;
    }
    if challenge_proof
        .get("proof")
        .is_none_or(|value| matches!(value, Value::Null))
    {
        return false;
    }
    let Some(max_age) = gate
        .get("max_proof_age")
        .and_then(Value::as_str)
        .and_then(parse_iso8601_duration)
    else {
        return false;
    };
    let Some(issued_at) = challenge_proof
        .get("issued_at")
        .and_then(Value::as_str)
        .and_then(parse_rfc3339_timestamp)
    else {
        return false;
    };
    let age = now.signed_duration_since(issued_at);
    age >= Duration::seconds(-60) && age <= max_age
}

fn challenge_kind_allowed(
    gate: &serde_json::Map<String, Value>,
    challenge_proof: &serde_json::Map<String, Value>,
) -> bool {
    let allowed = |kind: &str| {
        gate.get("challenge_kinds")
            .and_then(Value::as_array)
            .is_some_and(|kinds| kinds.iter().any(|value| value.as_str() == Some(kind)))
    };
    if let Some(kind) = challenge_proof
        .get("challenge_kind")
        .or_else(|| challenge_proof.get("kind"))
        .and_then(Value::as_str)
    {
        return allowed(kind);
    }
    if let Some(kinds) = challenge_proof
        .get("challenge_kinds")
        .and_then(Value::as_array)
    {
        return kinds.iter().filter_map(Value::as_str).any(allowed);
    }
    false
}

pub(crate) fn parse_rfc3339_timestamp(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|timestamp| timestamp.with_timezone(&Utc))
}

pub(crate) fn parse_iso8601_duration(value: &str) -> Option<Duration> {
    let rest = value.strip_prefix('P')?;
    if rest.is_empty() {
        return None;
    }
    let mut total_seconds: i64 = 0;
    let mut digits = String::new();
    let mut in_time = false;
    for ch in rest.chars() {
        if ch == 'T' {
            if in_time || !digits.is_empty() {
                return None;
            }
            in_time = true;
            continue;
        }
        if ch.is_ascii_digit() {
            digits.push(ch);
            continue;
        }
        if digits.is_empty() {
            return None;
        }
        let value = digits.parse::<i64>().ok()?;
        digits.clear();
        let scale = match (in_time, ch) {
            (false, 'Y') => 365 * 24 * 60 * 60,
            (false, 'M') => 30 * 24 * 60 * 60,
            (false, 'W') => 7 * 24 * 60 * 60,
            (false, 'D') => 24 * 60 * 60,
            (true, 'H') => 60 * 60,
            (true, 'M') => 60,
            (true, 'S') => 1,
            _ => return None,
        };
        total_seconds = total_seconds.checked_add(value.checked_mul(scale)?)?;
    }
    if !digits.is_empty() {
        return None;
    }
    Some(Duration::seconds(total_seconds))
}

/// `morph.md` §4.1 S3 — collect the opt-in conformance profile ids a Realm
/// lifecycle event declares. Reads `active_profiles[]` / `profiles[]` from the
/// payload root, the `object` block, and a `patch.active_profiles` register set
/// (so `ak.realm.update` declarations are captured as well). Only well-formed
/// `ak.profile.*` strings are returned.
pub(crate) fn realm_declared_profiles(operation: &Operation) -> Vec<String> {
    let mut profiles = Vec::new();
    let mut push_array = |value: Option<&Value>| {
        if let Some(items) = value.and_then(Value::as_array) {
            for item in items {
                if let Some(id) = item.as_str().filter(|id| id.starts_with("ak.profile.")) {
                    let owned = id.to_owned();
                    if !profiles.contains(&owned) {
                        profiles.push(owned);
                    }
                }
            }
        }
    };
    for field in ["active_profiles", "profiles"] {
        push_array(operation.payload.get(field));
        push_array(
            operation
                .payload
                .get("object")
                .and_then(|object| object.get(field)),
        );
        // `ak.realm.update` carries mutable fields in the patch register; a
        // `patch.active_profiles: { "$op": "set", "value": [...] }` (or the
        // direct-array sugar) declares the profile set.
        if let Some(patch_field) = operation
            .payload
            .get("patch")
            .and_then(|patch| patch.get(field))
        {
            match patch_field {
                Value::Array(_) => push_array(Some(patch_field)),
                Value::Object(op) if op.get("$op").and_then(Value::as_str) == Some("set") => {
                    push_array(op.get("value"));
                }
                _ => {}
            }
        }
    }
    profiles
}

pub(crate) fn operation_encryption_profile(operation: &Operation) -> Option<&str> {
    operation
        .payload
        .get("encryption_profile")
        .and_then(Value::as_str)
        .or_else(|| {
            operation
                .payload
                .get("object")
                .and_then(|object| object.get("encryption_profile"))
                .and_then(Value::as_str)
        })
}

pub(crate) fn operation_touches_encryption_profile(operation: &Operation) -> bool {
    operation.payload.get("encryption_profile").is_some()
        || operation
            .payload
            .get("object")
            .is_some_and(|object| value_has_direct_field(object, "encryption_profile"))
        || operation_patch_touches_field(&operation.payload, "encryption_profile")
}

pub(crate) fn operation_touches_digest_algorithm(operation: &Operation) -> bool {
    operation.payload.get("digest_algorithm").is_some()
        || operation
            .payload
            .get("object")
            .is_some_and(|object| value_has_direct_field(object, "digest_algorithm"))
        || operation_patch_touches_field(&operation.payload, "digest_algorithm")
}

pub(crate) fn value_has_direct_field(value: &Value, field: &str) -> bool {
    value
        .as_object()
        .is_some_and(|object| object.contains_key(field))
}

pub(crate) fn operation_patch_touches_field(payload: &Value, field: &str) -> bool {
    payload
        .get("patch")
        .and_then(Value::as_object)
        .is_some_and(|patch| {
            patch.iter().any(|(key, value)| {
                patch_key_touches_field(key, field)
                    || (key == "object" && patch_value_has_direct_field(value, field))
            })
        })
}

pub(crate) fn patch_key_touches_field(key: &str, field: &str) -> bool {
    let dotted = format!("{field}.");
    let pointer = format!("/{field}");
    let pointer_child = format!("/{field}/");
    let object_dotted = format!("object.{field}");
    let object_dotted_child = format!("object.{field}.");
    let object_pointer = format!("/object/{field}");
    let object_pointer_child = format!("/object/{field}/");
    key == field
        || key.starts_with(&dotted)
        || key == pointer
        || key.starts_with(&pointer_child)
        || key == object_dotted
        || key.starts_with(&object_dotted_child)
        || key == object_pointer
        || key.starts_with(&object_pointer_child)
}

pub(crate) fn patch_value_has_direct_field(value: &Value, field: &str) -> bool {
    value
        .get("value")
        .unwrap_or(value)
        .as_object()
        .is_some_and(|object| object.contains_key(field))
}

pub(crate) fn encryption_profile_requires_content_encryption(profile: Option<&str>) -> bool {
    profile
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some_and(|profile| !matches!(profile, "none" | "plaintext" | "allow_plaintext"))
}

/// Extract an encryption-floor field from a `ak.realm.policy_components`
/// value, accepting both the top-level and `/components/`-nested wire forms
/// (mirrors `realm_join_policy_cell_value`).
pub(crate) fn policy_floor_field<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value
        .get(field)
        .or_else(|| value.pointer(&format!("/components/{field}")))
        .and_then(Value::as_str)
}

/// Ordinal rank for `content_encryption_floor` (`allow_plaintext < e2ee_required`).
/// `None` / unknown values rank as `allow_plaintext` (0); spec default is
/// `allow_plaintext` (realm-and-space.md §2.3, circle.md §7).
pub(crate) fn content_floor_rank(floor: Option<&str>) -> u8 {
    match floor.map(str::trim) {
        Some("e2ee_required") => 1,
        _ => 0,
    }
}

/// Ordinal rank for the metadata encryption floor
/// (`allow_plaintext < e2ee_required`), symmetric with the content floor.
/// `None` / unknown ranks as `allow_plaintext` (0).
pub(crate) fn metadata_floor_rank(floor: Option<&str>) -> u8 {
    match floor.map(str::trim) {
        Some("e2ee_required") => 1,
        _ => 0,
    }
}

/// Extract the Realm `content_scheme` field from a `ak.realm.policy_components`
/// value, accepting both the top-level and `/components/`-nested wire forms
/// (mirrors [`policy_floor_field`]). Returns `None` when the field is absent.
pub(crate) fn content_scheme_field(value: &Value) -> Option<&str> {
    policy_floor_field(value, "content_scheme")
}

/// Ordinal rank for the Realm `content_scheme`. The exporter-derived AEAD scheme
/// (`mls-exporter-aead-v1`, rank 1) sits above the MLS application-message scheme
/// (`mls-rfc9420`, rank 0). `None` / unknown values rank as `mls-rfc9420` (0);
/// the one-way ratchet rejects any later write whose rank is strictly lower than
/// the projected scheme.
pub(crate) fn content_scheme_rank(scheme: Option<&str>) -> u8 {
    match scheme.map(str::trim) {
        Some("mls-exporter-aead-v1") => 1,
        _ => 0,
    }
}

/// The canonical Realm `content_scheme` enum
/// (realm-and-space.md history-sharing): `mls-rfc9420` (application messages) and
/// `mls-exporter-aead-v1` (exporter-derived AEAD content for history sharing).
pub(crate) fn content_scheme_is_known(scheme: &str) -> bool {
    matches!(scheme.trim(), "mls-rfc9420" | "mls-exporter-aead-v1")
}

/// Extract the `durability_policy` object from a `ak.realm.policy_components`
/// value, accepting both the top-level and `/components/`-nested wire forms
/// (mirrors [`policy_floor_field`]). Returns `None` when the field is absent.
pub(crate) fn durability_policy_field(value: &Value) -> Option<&Value> {
    value
        .get("durability_policy")
        .or_else(|| value.pointer("/components/durability_policy"))
        .filter(|policy| policy.is_object())
}

/// realm-and-space.md §2.3.1 — validate an incoming `durability_policy` against
/// its structural invariants and the effective `content_scheme`. `scheme` is the
/// Realm's effective `content_scheme` *after* applying this policy update (the
/// incoming scheme when present, else the already-projected scheme).
///
/// - `mode != none` requires a non-empty `recovery_recipients` array → `durability_policy_invalid`
///   otherwise.
/// - `mode=threshold` requires `threshold.{k,n}` with `1 <= k <= n == len(recovery_recipients)` →
///   `durability_policy_invalid` otherwise.
/// - `mode != none` is only valid on `content_scheme=mls-exporter-aead-v1` →
///   `durability_scheme_incompatible` otherwise (the spec failed_precondition).
pub(crate) fn validate_durability_policy(
    policy: &Value,
    effective_scheme: Option<&str>,
) -> Result<(), &'static str> {
    let mode = policy.get("mode").and_then(Value::as_str).unwrap_or("none");
    if !matches!(mode, "none" | "org_recovery_key" | "threshold") {
        return Err(DURABILITY_POLICY_INVALID);
    }
    if mode == "none" {
        return Ok(());
    }
    // mode != none — recovery_recipients MUST be non-empty and unique.
    let recipients = policy
        .get("recovery_recipients")
        .and_then(Value::as_array)
        .filter(|recipients| !recipients.is_empty())
        .ok_or(DURABILITY_POLICY_INVALID)?;
    // scheme gate: organizational recovery requires a deliverable history_secret.
    if content_scheme_rank(effective_scheme) < content_scheme_rank(Some("mls-exporter-aead-v1")) {
        return Err(DURABILITY_SCHEME_INCOMPATIBLE);
    }
    if mode == "threshold" {
        let threshold = policy
            .get("threshold")
            .and_then(Value::as_object)
            .ok_or(DURABILITY_POLICY_INVALID)?;
        let k = threshold.get("k").and_then(Value::as_u64);
        let n = threshold.get("n").and_then(Value::as_u64);
        let (Some(k), Some(n)) = (k, n) else {
            return Err(DURABILITY_POLICY_INVALID);
        };
        if k < 1 || k > n || n != recipients.len() as u64 {
            return Err(DURABILITY_POLICY_INVALID);
        }
    }
    Ok(())
}
