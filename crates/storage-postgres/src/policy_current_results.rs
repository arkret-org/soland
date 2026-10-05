//! Same-cut semantic checks and RealmCommit-bound Policy current writers.
use arkret_models_collaboration::events_payloads::{PolicyActionStatePayload, PolicyActionSubject};
use arkret_models_collaboration::governance::operation_wire::{
    PolicySetStatePayload, PolicySetValue,
};
use arkret_wire::{CapabilityActionId, Event, EventKind, RealmCommit, WireResourceSelector};
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::Value;
use soland_storage::{PersistenceError, PersistenceResult};

#[derive(QueryableByName)]
struct Stored {
    #[diesel(sql_type=Text)]
    realm_id: String,
    #[diesel(sql_type=Jsonb)]
    value: Value,
}
fn schema(e: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::SchemaViolation(e.to_string())
}
fn refused(e: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("failed_precondition: {e}"))
}
fn require_supported_policy_kind(kind: arkret_wire::PolicyKind) -> PersistenceResult<()> {
    if kind == arkret_wire::PolicyKind::Agent {
        return Err(refused(
            "Agent management execution and delivery gates are not established",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod admission_tests {
    use super::*;

    #[test]
    fn agent_policy_is_refused_even_without_an_agent_rule() {
        let payload: PolicySetStatePayload = serde_json::from_value(serde_json::json!({
            "policy_id": "ak:policy:0198ff00-0000-7000-8000-000000000001",
            "expected_revision": null,
            "value": {
                "schema": "ak.schema.policy.v1",
                "id": "ak:policy:0198ff00-0000-7000-8000-000000000001",
                "realm_id": "ak:realm:AT47eNekH0_aKZyIMsXq_s1FAWdYXC71_CUxQ5O478t-",
                "policy_kind": "agent",
                "rules": [{"rule_id": "ordinary", "kind": "action", "effect": "allow", "actions": ["ak.message.create"]}],
                "default_effect": "deny",
                "created_by": {"kind": "account", "account_id": {
                    "principal_id": "ak:did_core:webvh:z6mkfixturecontroller",
                    "station_id": "ak:did_core:webvh:z6mkfixturestation"
                }},
                "created_at": "2026-10-05T11:15:00.000Z"
            }
        })).unwrap();
        payload.validate().unwrap();
        let PolicySetValue::Governance(document) = payload.value else {
            panic!("expected governance policy");
        };
        assert!(require_supported_policy_kind(document.policy_kind).is_err());
    }

    #[test]
    fn ordinary_policy_kinds_keep_their_existing_admission() {
        assert!(require_supported_policy_kind(arkret_wire::PolicyKind::Access).is_ok());
        assert!(require_supported_policy_kind(arkret_wire::PolicyKind::Join).is_ok());
    }
}
fn payload<T: serde::de::DeserializeOwned>(event: &Event) -> PersistenceResult<T> {
    serde_json::from_value(serde_json::to_value(&event.payload).map_err(schema)?).map_err(schema)
}

/// Resolve the precise declared scope from current authority, rather than
/// weakening an object scope into Realm-wide authorization.
pub(crate) async fn resolve_scope(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    scope: &str,
) -> PersistenceResult<WireResourceSelector> {
    if let Ok(id) = arkret_wire::RealmId::new(scope) {
        if &id != realm {
            return Err(refused("Policy scope belongs to another Realm"));
        }
        return Ok(WireResourceSelector::realm(id));
    }
    let (table, column, target) = if let Ok(id) = arkret_wire::SpaceId::new(scope) {
        (
            "space_current_results",
            "space_id",
            WireResourceSelector::space(realm.clone(), id),
        )
    } else if let Ok(id) = arkret_wire::StrandId::new(scope) {
        (
            "strand_current_results",
            "strand_id",
            WireResourceSelector::strand(realm.clone(), id),
        )
    } else if let Ok(id) = arkret_wire::CircleId::new(scope) {
        (
            "circle_current_results",
            "circle_id",
            WireResourceSelector::circle(realm.clone(), id),
        )
    } else if let Ok(id) = arkret_wire::PolicyId::new(scope) {
        (
            "policy_current_results",
            "policy_id",
            serde_json::from_value(
                serde_json::json!({"kind":"policy","realm_id":realm,"policy_id":id}),
            )
            .map_err(schema)?,
        )
    } else if let Ok(did) = arkret_wire::Did::new(scope) {
        let principal = arkret_wire::project_did_to_core_id(&did).map_err(schema)?;
        #[derive(QueryableByName)]
        struct Exists {
            #[diesel(sql_type=diesel::sql_types::Bool)]
            present: bool,
        }
        let exists=sql_query("SELECT EXISTS(SELECT 1 FROM member_state_current_results WHERE realm_id=$1 AND ((member_id::jsonb->'account_id'->>'principal_id')=$2 OR (member_id::jsonb->>'service_id')=$2)) AS present")
            .bind::<Text,_>(realm.as_str()).bind::<Text,_>(principal.as_str())
            .get_result::<Exists>(&mut *conn).await.map_err(PersistenceError::database)?;
        if !exists.present {
            return Err(refused(
                "Policy DID scope has no member authority in this Realm",
            ));
        }
        return serde_json::from_value(
            serde_json::json!({"kind":"actor","realm_id":realm,"actor_id":principal}),
        )
        .map_err(schema);
    } else {
        return Err(refused("Policy scope has no resolvable typed authority"));
    };
    let row = sql_query(format!(
        "SELECT realm_id,value FROM {table} WHERE {column}=$1"
    ))
    .bind::<Text, _>(scope)
    .get_result::<Stored>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| refused("Policy scope current object is unavailable"))?;
    if row.realm_id != realm.as_str() {
        return Err(refused("Policy scope belongs to another Realm"));
    }
    Ok(target)
}

pub(crate) async fn admit_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
) -> PersistenceResult<Option<WireResourceSelector>> {
    match event.kind {
        EventKind::PolicySet => {
            let value: PolicySetStatePayload = payload(event)?;
            value.validate().map_err(schema)?;
            if let PolicySetValue::Governance(document) = value.value {
                // Do not acknowledge a restriction that the current read and
                // delivery paths cannot yet enforce at their actual cut.
                require_supported_policy_kind(document.policy_kind)?;
                if document
                    .realm_id
                    .as_ref()
                    .is_some_and(|id| id != &event.realm_id)
                {
                    return Err(schema(
                        "Policy document Realm differs from its accepting Realm",
                    ));
                }
                return Ok(Some(WireResourceSelector::realm(event.realm_id.clone())));
            }
            Err(refused(
                "Recovery Policy is admitted through its dedicated PCR unit",
            ))
        }
        EventKind::PolicyAction => {
            let config: PolicyActionStatePayload = payload(event)?;
            config.validate().map_err(schema)?;
            let action = CapabilityActionId::from_wire(config.value.action.as_str())
                .ok_or_else(|| schema("Policy action is not registered"))?;
            if config.value.approval_required {
                crate::policy_action_admission::require_registered_carrier(action)?;
            }
            let target = resolve_scope(conn, &event.realm_id, &config.value.policy_scope).await?;
            match config.subject().map_err(schema)? {
                PolicyActionSubject::Policy(id) => {
                    let policy = sql_query(
                        "SELECT realm_id,value FROM policy_current_results WHERE policy_id=$1",
                    )
                    .bind::<Text, _>(id.as_str())
                    .get_result::<Stored>(&mut *conn)
                    .await
                    .optional()
                    .map_err(PersistenceError::database)?
                    .ok_or_else(|| refused("Policy action dependency is unavailable"))?;
                    if policy.realm_id != event.realm_id.as_str() {
                        return Err(refused("Policy action dependency is outside this Realm"));
                    }
                    let value: PolicySetValue =
                        serde_json::from_value(policy.value).map_err(schema)?;
                    if !matches!(value, PolicySetValue::Governance(_)) {
                        return Err(refused(
                            "Recovery Policy cannot carry governance approval configuration",
                        ));
                    }
                }
                PolicyActionSubject::Action(id) => {
                    let previous=sql_query("SELECT realm_id,value FROM policy_action_current_results WHERE realm_id=$1 AND subject_kind='realm_action' AND subject_id=$2 AND action_key=''")
                        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(id.as_str())
                        .get_result::<Stored>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
                    if let Some(previous) = previous {
                        let value:arkret_models_collaboration::events_payloads::PolicyActionDocument=serde_json::from_value(previous.value).map_err(schema)?;
                        if value.action != config.value.action
                            || value.policy_scope != config.value.policy_scope
                        {
                            return Err(refused("Realm-local Policy action cannot be rebound"));
                        }
                    }
                }
            }
            Ok(Some(target))
        }
        _ => Ok(None),
    }
}

pub(crate) async fn commit_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    match event.kind {
        EventKind::PolicySet => {
            let payload: PolicySetStatePayload = payload(event)?;
            payload.validate().map_err(schema)?;
            let value = serde_json::to_value(&payload.value).map_err(schema)?;
            let count=sql_query("INSERT INTO policy_current_results(realm_id,policy_id,current_commit_id,current_stream_position,current_event_id,value,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(policy_id) DO UPDATE SET current_commit_id=EXCLUDED.current_commit_id,current_stream_position=EXCLUDED.current_stream_position,current_event_id=EXCLUDED.current_event_id,value=EXCLUDED.value,updated_at=EXCLUDED.updated_at WHERE policy_current_results.realm_id=EXCLUDED.realm_id AND policy_current_results.current_stream_position<EXCLUDED.current_stream_position")
                .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(payload.policy_id.as_str()).bind::<Text,_>(commit.commit_id.as_str())
                .bind::<BigInt,_>(commit.stream_position as i64).bind::<Text,_>(event.event_id.as_str()).bind::<Jsonb,_>(&value)
                .bind::<Timestamptz,_>(commit.committed_at).execute(&mut *conn).await.map_err(PersistenceError::database)?;
            if count != 1 {
                return Err(refused(
                    "Policy current cannot cross Realm or move backwards",
                ));
            }
        }
        EventKind::PolicyAction => {
            let payload: PolicyActionStatePayload = payload(event)?;
            payload.validate().map_err(schema)?;
            let (kind, id, key) = match payload.subject().map_err(schema)? {
                PolicyActionSubject::Policy(id) => (
                    "policy_ref",
                    id.to_string(),
                    payload.value.action.as_str().to_owned(),
                ),
                PolicyActionSubject::Action(id) => {
                    ("realm_action", id.as_str().to_owned(), String::new())
                }
            };
            let value = serde_json::to_value(payload.value).map_err(schema)?;
            let count=sql_query("INSERT INTO policy_action_current_results(realm_id,subject_kind,subject_id,action_key,current_commit_id,current_stream_position,current_event_id,value,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(realm_id,subject_kind,subject_id,action_key) DO UPDATE SET current_commit_id=EXCLUDED.current_commit_id,current_stream_position=EXCLUDED.current_stream_position,current_event_id=EXCLUDED.current_event_id,value=EXCLUDED.value,updated_at=EXCLUDED.updated_at WHERE policy_action_current_results.current_stream_position<EXCLUDED.current_stream_position")
                .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(kind).bind::<Text,_>(id).bind::<Text,_>(key)
                .bind::<Text,_>(commit.commit_id.as_str()).bind::<BigInt,_>(commit.stream_position as i64)
                .bind::<Text,_>(event.event_id.as_str()).bind::<Jsonb,_>(&value).bind::<Timestamptz,_>(commit.committed_at)
                .execute(&mut *conn).await.map_err(PersistenceError::database)?;
            if count != 1 {
                return Err(refused("Policy action current cannot move backwards"));
            }
        }
        _ => {}
    }
    Ok(())
}
