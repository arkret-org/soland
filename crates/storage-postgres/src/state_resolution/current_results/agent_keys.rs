//! Effective Agent key projection from the already joined OR-Set.

use arkret_models_collaboration::events_payloads::agent::{
    AgentKeyAuthorizePayload, AgentKeyRevokePayload, AgentKeyScope, AgentKeyScopeResource,
};
use chrono::{DateTime, Utc};

use super::*;

fn inactive(reason: &str) -> Value {
    serde_json::json!({"status":"value","value":{"status":"inactive","reason":reason}})
}

fn bottom() -> Value {
    serde_json::json!({"status":"unavailable","reason":"bottom"})
}

fn overlap<T: Clone + PartialEq>(left: &Option<T>, right: &Option<T>) -> Option<Option<T>> {
    match (left, right) {
        (Some(a), Some(b)) if a != b => None,
        (Some(value), _) | (_, Some(value)) => Some(Some(value.clone())),
        (None, None) => Some(None),
    }
}

fn intersect_resource(
    a: &AgentKeyScopeResource,
    b: &AgentKeyScopeResource,
) -> Option<AgentKeyScopeResource> {
    if a.kind != b.kind {
        return None;
    }
    Some(AgentKeyScopeResource {
        kind: a.kind,
        realm_id: overlap(&a.realm_id, &b.realm_id)?,
        resource_ref: overlap(&a.resource_ref, &b.resource_ref)?,
        schema_ref: overlap(&a.schema_ref, &b.schema_ref)?,
        operation: overlap(&a.operation, &b.operation)?,
        service_id: overlap(&a.service_id, &b.service_id)?,
    })
}

fn dedup<T: serde::Serialize>(
    values: impl IntoIterator<Item = T>,
) -> Result<Vec<T>, EventSealCommitError> {
    let mut unique = BTreeMap::new();
    for value in values {
        unique.insert(
            arkret_canonical::canonical_json_bytes(&value).map_err(invalid)?,
            value,
        );
    }
    Ok(unique.into_values().collect())
}

fn intersect_scope(
    left: &AgentKeyScope,
    right: &AgentKeyScope,
) -> Result<AgentKeyScope, EventSealCommitError> {
    let actions = left
        .actions
        .iter()
        .filter(|v| right.actions.contains(v))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let resources = dedup(left.resources.iter().flat_map(|a| {
        right
            .resources
            .iter()
            .filter_map(move |b| intersect_resource(a, b))
    }))?;
    // Constraints are conjunctive; retaining both is the strict intersection.
    let constraints = dedup(left.constraints.iter().chain(&right.constraints).cloned())?;
    Ok(AgentKeyScope {
        actions,
        resources,
        constraints,
    })
}

pub(super) fn fold(
    value: &Value,
    lifecycles: &BTreeMap<String, ResolvedCellState>,
    now: DateTime<Utc>,
) -> Result<(Value, Option<DateTime<Utc>>), EventSealCommitError> {
    let items = value
        .as_array()
        .ok_or_else(|| invalid("Agent key OR-Set is not an array"))?;
    let mut authorizations = Vec::new();
    let mut revoked = false;
    for item in items {
        let value = item
            .get("value")
            .ok_or_else(|| invalid("Agent key dot has no value"))?;
        if serde_json::from_value::<AgentKeyRevokePayload>(value.clone()).is_ok() {
            revoked = true;
            continue;
        }
        let authorization =
            serde_json::from_value::<AgentKeyAuthorizePayload>(value.clone()).map_err(invalid)?;
        let tag = item
            .get("tag")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("Agent key dot has no canonical tag"))?;
        let (event, index) = tag
            .rsplit_once(':')
            .ok_or_else(|| invalid("Agent key dot is malformed"))?;
        let index_value = index.parse::<usize>().map_err(invalid)?;
        if index_value.to_string() != index {
            return Err(invalid("Agent key dot index is noncanonical"));
        }
        let event = arkret_wire::EventId::new(event.to_owned()).map_err(invalid)?;
        authorizations.push((event, authorization));
    }
    // Replacement removes only the exact superseded authorization dot.
    // Revoke dots remain in their old key cell and keep that raw key revoked.
    if revoked {
        return Ok((inactive("revoked"), None));
    }
    let Some((_, first)) = authorizations.as_slice().first() else {
        return Ok((inactive("absent"), None));
    };
    let Some(lifecycle) = lifecycles.get(first.agent_id.as_str()) else {
        return Err(invalid("Agent key has no exact accepted lifecycle origin"));
    };
    match lifecycle {
        ResolvedCellState::Bottom(_) => return Ok((bottom(), None)),
        ResolvedCellState::Value(value) if value.as_str() == Some("active") => {}
        _ => return Ok((inactive("lifecycle_inactive"), None)),
    }
    let mut scope = first.agent_key_scope.clone();
    let mut audience = first.audience.iter().cloned().collect::<BTreeSet<_>>();
    let mut expiry = first.expires_at;
    for (_, next) in authorizations.iter().skip(1) {
        if first.agent_id != next.agent_id
            || first.key_id != next.key_id
            || first.verification_method != next.verification_method
            || first.public_key != next.public_key
            || first.accountable_principal_id != next.accountable_principal_id
        {
            return Ok((bottom(), None));
        }
        scope = intersect_scope(&scope, &next.agent_key_scope)?;
        audience.retain(|value| next.audience.contains(value));
        expiry = match (expiry, next.expires_at) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
    }
    if expiry.is_some_and(|expiry| expiry <= now) {
        return Ok((inactive("expired"), None));
    }
    if scope.actions.is_empty() || scope.resources.is_empty() || audience.is_empty() {
        return Ok((inactive("empty_scope"), None));
    }
    let mut events = authorizations
        .iter()
        .map(|(event, _)| event.clone())
        .collect::<Vec<_>>();
    events.sort_by_key(|event| event.token_bytes());
    events.dedup();
    let mut value = serde_json::json!({"status":"active","agent_id":first.agent_id,"key_id":first.key_id,
        "verification_method":first.verification_method,"public_key":first.public_key,
        "accountable_principal_id":first.accountable_principal_id,"agent_key_scope":scope,
        "audience":audience,"authorization_event_ids":events});
    if let Some(expiry) = expiry {
        value["expires_at"] = Value::String(arkret_canonical::format_timestamp_canonical(expiry));
    }
    Ok((serde_json::json!({"status":"value","value":value}), expiry))
}

#[cfg(test)]
pub(super) mod tests {
    use arkret_models_collaboration::events_payloads::agent::AgentKeyScopeResourceKind;

    use super::*;

    pub(crate) fn authorization(
        byte: u8,
        expiry: &str,
        actions: &[&str],
        audience: &[&str],
    ) -> Value {
        let event =
            arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [byte; 32]);
        serde_json::json!({"tag":format!("{event}:1"),"value":{
            "agent_id":"ak:did_core:web:agent.example","key_id":"runtime-key",
            "verification_method":"did:web:agent.example#runtime-key",
            "public_key":{"kty":"OKP","kid":"did:web:agent.example#key-1","algorithm":"Ed25519","key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
            "accountable_principal_id":"ak:did_core:web:controller.example",
            "agent_key_scope":{"actions":actions,"resources":[{"kind":"operation","operation":"ak.self.account.stream.subscribe.v1"}]},
            "audience":audience,"issued_at":"2026-09-10T00:00:00.000Z","expires_at":expiry,
            "approval_evidence":{"kind":"approval_event"}}})
    }

    #[test]
    fn concurrent_authorizations_fold_strictly_and_expire_without_an_event() {
        let now = DateTime::parse_from_rfc3339("2026-09-10T00:01:00.000Z")
            .unwrap()
            .with_timezone(&Utc);
        let lifecycle = BTreeMap::from([(
            "ak:did_core:web:agent.example".into(),
            ResolvedCellState::Value(Value::String("active".into())),
        )]);
        let value = serde_json::json!([
            authorization(1, "2026-09-10T00:05:00.000Z", &["a", "b"], &["one", "two"]),
            authorization(
                2,
                "2026-09-10T00:10:00.000Z",
                &["b", "c"],
                &["two", "three"]
            )
        ]);
        let (active, expiry) = fold(&value, &lifecycle, now).unwrap();
        assert_eq!(
            active["value"]["agent_key_scope"]["actions"],
            serde_json::json!(["b"])
        );
        assert_eq!(active["value"]["audience"], serde_json::json!(["two"]));
        assert_eq!(
            active["value"]["authorization_event_ids"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        let (expired, next_expiry) = fold(&value, &lifecycle, expiry.unwrap()).unwrap();
        assert_eq!(expired, inactive("expired"));
        assert!(next_expiry.is_none());
        let mut conflict = value.clone();
        conflict[1]["value"]["verification_method"] =
            Value::String("did:web:agent.example#other".into());
        assert_eq!(fold(&conflict, &lifecycle, now).unwrap().0, bottom());
        let mut revoked = value.clone();
        revoked.as_array_mut().unwrap().push(serde_json::json!({"tag":"unused","value":{
            "agent_id":"ak:did_core:web:agent.example","key_id":"runtime-key",
            "revoked_by":"ak:did_core:web:controller.example","revoked_at":"2026-09-10T00:00:00.000Z"}}));
        assert_eq!(
            fold(&revoked, &lifecycle, now).unwrap().0,
            inactive("revoked")
        );
    }

    #[test]
    fn resource_intersection_preserves_narrow_fields_and_rejects_disjoint_kinds() {
        let broad = AgentKeyScopeResource {
            kind: AgentKeyScopeResourceKind::Operation,
            realm_id: None,
            resource_ref: None,
            schema_ref: None,
            operation: None,
            service_id: None,
        };
        let mut narrow = broad.clone();
        narrow.operation = Some("ak.self.account.stream.subscribe.v1".into());
        assert_eq!(intersect_resource(&broad, &narrow), Some(narrow.clone()));
        let mut other = narrow.clone();
        other.operation = Some("ak.self.events.command.submit.v1".into());
        assert!(intersect_resource(&narrow, &other).is_none());
        other.kind = AgentKeyScopeResourceKind::Service;
        assert!(intersect_resource(&broad, &other).is_none());
    }
}
