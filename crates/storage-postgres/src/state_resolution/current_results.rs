//! Governance current-result publication at the verified Seal boundary.
//!
//! Origin rows preserve otherwise irreversible subject/target associations.
//! They are not current heads and are never used as a latest-event shortcut.

use arkret_models_collaboration::sync_frames::current_results::{
    CurrentResultEntry, CurrentSelector, CurrentTarget, current_family_descriptor,
    current_family_descriptors,
};
use arkret_wire::{ActorId, CellId, CircleId, ScopeRef, StrandId};

use super::*;

mod agent_keys;
#[cfg(test)]
mod pg_tests;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CurrentMvHead {
    event_id: arkret_wire::EventId,
    value: Value,
}

pub(super) type CurrentMvHeads = BTreeMap<CellRef, Vec<CurrentMvHead>>;

/// A head disappears only when another frozen parent view covers its write
/// but has already replaced it. Concurrent parent heads remain distinct.
pub(super) fn merge_mv_views(
    views: &[(CurrentMvHeads, BTreeSet<String>)],
) -> StoreResult<CurrentMvHeads> {
    let mut result = BTreeMap::<CellRef, BTreeMap<arkret_wire::EventId, CurrentMvHead>>::new();
    for (heads, _) in views {
        for (cell, candidates) in heads {
            for candidate in candidates {
                let digest = candidate.event_id.event_digest().to_string();
                let superseded = views.iter().any(|(other, covered)| {
                    covered.contains(&digest)
                        && !other.get(cell).is_some_and(|heads| {
                            heads.iter().any(|head| head.event_id == candidate.event_id)
                        })
                });
                if !superseded {
                    let heads = result.entry(cell.clone()).or_default();
                    if heads
                        .get(&candidate.event_id)
                        .is_some_and(|old| old.value != candidate.value)
                    {
                        return Err(StoreError::Backend(
                            "same MV source has inconsistent materialized values".into(),
                        ));
                    }
                    heads.insert(candidate.event_id.clone(), candidate.clone());
                }
            }
        }
    }
    Ok(result
        .into_iter()
        .map(|(cell, heads)| {
            let mut heads = heads.into_values().collect::<Vec<_>>();
            heads.sort_by_key(|head| head.event_id.token_bytes());
            (cell, heads)
        })
        .collect())
}

pub(super) async fn advance_mv_heads(
    conn: &mut AsyncPgConnection,
    realm: &str,
    predecessors: &[String],
    new_rows: &[(i64, String, String, Value)],
    rule_context: &CheckpointRuleContext,
) -> Result<(CurrentMvHeads, bool), EventSealCommitError> {
    let mut views = Vec::new();
    let mut ready = true;
    for predecessor in predecessors {
        let row = sql_query("SELECT realm_id, covered_event_digests, covered_seal_ids, state_json FROM state_seal_effective_checkpoints WHERE seal_id=$1")
            .bind::<Text,_>(predecessor).get_result::<EffectiveStateCheckpointRow>(&mut *conn).await.optional()?;
        let Some(row) = row else {
            ready = false;
            continue;
        };
        let view = checkpoint_view_from_value(row.state_json)?;
        if row.realm_id != realm || !row.covered_seal_ids.contains(predecessor) {
            ready = false;
            continue;
        }
        let heads = if view.rule_context.reusable_with(rule_context) && view.current_mv_ready {
            view.current_mv_heads
        } else {
            let Some(heads) = rebuild_mv_heads(
                conn,
                realm,
                &row.covered_seal_ids,
                &row.covered_event_digests,
                rule_context,
            )
            .await?
            else {
                ready = false;
                continue;
            };
            heads
        };
        views.push((heads, row.covered_event_digests.into_iter().collect()));
    }
    let mut heads = merge_mv_views(&views)?;
    let mut updates = CurrentMvHeads::new();
    for (_, cell, _, value) in new_rows {
        let cell = CellRef::new(cell.clone()).map_err(invalid)?;
        let parsed = CellId::from_ref(&cell).map_err(invalid)?;
        if !current_family_descriptor(parsed.component())
            .map_err(invalid)?
            .is_some_and(|d| d.lattice == "mv_register")
        {
            continue;
        }
        let issued = sealed_op_from_value(value.clone())?;
        let Some(value) = issued.op.op.value else {
            ready = false;
            continue;
        };
        let event_id =
            arkret_wire::EventId::from_event_digest(&issued.op.move_id).map_err(invalid)?;
        updates
            .entry(cell)
            .or_default()
            .push(CurrentMvHead { event_id, value });
    }
    for (cell, mut values) in updates {
        values.sort_by_key(|head| head.event_id.token_bytes());
        values.dedup_by(|a, b| a.event_id == b.event_id && a.value == b.value);
        heads.insert(cell, values);
    }
    Ok((heads, ready))
}

#[derive(QueryableByName)]
struct MvRebuildSeal {
    #[diesel(sql_type = Text)]
    seal_id: String,
    #[diesel(sql_type = Array<Text>)]
    covered_seal_ids: Vec<String>,
    #[diesel(sql_type = Array<Text>)]
    parents: Vec<String>,
}

/// Reconstruct provenance from accepted effects and Seal ancestry, never from
/// arrival order or an incompatible joined-value cache. Same-Seal writes stay
/// siblings; only writes in a strict successor Seal supersede a source.
pub(super) async fn rebuild_mv_heads(
    conn: &mut AsyncPgConnection,
    realm: &str,
    closure: &[String],
    covered: &[String],
    context: &CheckpointRuleContext,
) -> Result<Option<CurrentMvHeads>, EventSealCommitError> {
    if !matches!(context, CheckpointRuleContext::Stable { .. }) {
        return Ok(None);
    }
    let seals = sql_query("SELECT s.id AS seal_id,c.covered_seal_ids,ARRAY(SELECT jsonb_array_elements_text(s.predecessor_refs)) AS parents FROM state_seals s JOIN state_seal_effective_checkpoints c ON c.seal_id=s.id AND c.realm_id=s.realm_id WHERE s.realm_id=$1 AND s.id=ANY($2) AND NOT EXISTS(SELECT 1 FROM state_seal_quarantine q WHERE q.seal_id=s.id)")
        .bind::<Text,_>(realm).bind::<Array<Text>,_>(closure).load::<MvRebuildSeal>(&mut *conn).await?;
    let expected = closure.iter().cloned().collect::<BTreeSet<_>>();
    let actual = seals
        .iter()
        .map(|s| s.seal_id.clone())
        .collect::<BTreeSet<_>>();
    if expected != actual {
        return Ok(None);
    }
    let lineage = seals
        .iter()
        .map(|s| {
            (
                s.seal_id.clone(),
                s.covered_seal_ids.iter().cloned().collect::<BTreeSet<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    for seal in &seals {
        let ancestors = &lineage[&seal.seal_id];
        if !ancestors.contains(&seal.seal_id)
            || !ancestors.is_subset(&expected)
            || seal.parents.iter().any(|p| {
                p == &seal.seal_id || !ancestors.contains(p) || !lineage[p].is_subset(ancestors)
            })
            || ancestors
                .iter()
                .any(|a| a != &seal.seal_id && lineage[a].contains(&seal.seal_id))
        {
            return Ok(None);
        }
        let declared = seal
            .parents
            .iter()
            .flat_map(|p| lineage[p].iter().cloned())
            .chain(std::iter::once(seal.seal_id.clone()))
            .collect::<BTreeSet<_>>();
        if &declared != ancestors {
            return Ok(None);
        }
    }
    let rows = sql_query("SELECT cell_id,seal_id,op_json FROM state_cell_ops WHERE realm_id=$1 AND seal_id=ANY($2) AND move_id=ANY($3) ORDER BY cell_id,seq")
        .bind::<Text,_>(realm).bind::<Array<Text>,_>(closure).bind::<Array<Text>,_>(covered).load::<EventCellOpRow>(&mut *conn).await?;
    let mut writes = BTreeMap::<CellRef, Vec<(String, CurrentMvHead)>>::new();
    for row in rows {
        let cell = CellRef::new(row.cell_id).map_err(invalid)?;
        if !current_family_descriptor(CellId::from_ref(&cell).map_err(invalid)?.component())
            .map_err(invalid)?
            .is_some_and(|d| d.lattice == "mv_register")
        {
            continue;
        }
        let issued = sealed_op_from_value(row.op_json)?;
        let Some(value) = issued.op.op.value else {
            return Ok(None);
        };
        let event_id =
            arkret_wire::EventId::from_event_digest(&issued.op.move_id).map_err(invalid)?;
        writes
            .entry(cell)
            .or_default()
            .push((row.seal_id, CurrentMvHead { event_id, value }));
    }
    let mut result = CurrentMvHeads::new();
    for (cell, candidates) in writes {
        let mut surviving = BTreeMap::new();
        for (seal, head) in &candidates {
            if candidates
                .iter()
                .any(|(other, _)| other != seal && lineage[other].contains(seal))
            {
                continue;
            }
            if surviving
                .get(&head.event_id)
                .is_some_and(|old| old != &head.value)
            {
                return Err(invalid("same MV source has inconsistent accepted effects"));
            }
            surviving.insert(head.event_id.clone(), head.value.clone());
        }
        let mut heads = surviving
            .into_iter()
            .map(|(event_id, value)| CurrentMvHead { event_id, value })
            .collect::<Vec<_>>();
        heads.sort_by_key(|head| head.event_id.token_bytes());
        result.insert(cell, heads);
    }
    Ok(Some(result))
}

#[derive(QueryableByName)]
struct OriginEventRow {
    #[diesel(sql_type = Text)]
    cell_id: String,
    #[diesel(sql_type = Jsonb)]
    event_json: Value,
}

#[derive(QueryableByName)]
struct OriginRow {
    #[diesel(sql_type = Bool)]
    unwritten: bool,
    #[diesel(sql_type = Text)]
    cell_id: String,
    #[diesel(sql_type = Jsonb)]
    selector: Value,
    #[diesel(sql_type = Jsonb)]
    target: Value,
    #[diesel(sql_type = Binary)]
    source_event_id: Vec<u8>,
}

fn invalid(message: impl std::fmt::Display) -> EventSealCommitError {
    StoreError::Backend(message.to_string()).into()
}

pub(super) async fn invalidate(
    conn: &mut AsyncPgConnection,
    realm: &str,
    revision: i64,
) -> Result<(), diesel::result::Error> {
    sql_query("INSERT INTO governance_current_ready(realm_id,ready,revision) VALUES($1,FALSE,$2) ON CONFLICT(realm_id) DO UPDATE SET ready=FALSE,revision=EXCLUDED.revision")
        .bind::<Text,_>(realm).bind::<BigInt,_>(revision).execute(conn).await?;
    Ok(())
}

pub(super) async fn register_delta_origins(
    conn: &mut AsyncPgConnection,
    realm: &str,
    delta: &[String],
) -> Result<(), EventSealCommitError> {
    let rows = sql_query("SELECT DISTINCT op.cell_id,e.event_json FROM state_cell_ops op JOIN state_control_events e ON e.realm_id=op.realm_id AND e.event_digest=op.move_id WHERE op.realm_id=$1 AND op.move_id=ANY($2)")
        .bind::<Text,_>(realm).bind::<Array<Text>,_>(delta).load::<OriginEventRow>(&mut *conn).await?;
    let realm_id = RealmId::new(realm.to_owned()).map_err(invalid)?;
    for row in rows {
        let cell_ref = CellRef::new(row.cell_id).map_err(invalid)?;
        let cell = CellId::from_ref(&cell_ref).map_err(invalid)?;
        let Some(descriptor) = current_family_descriptor(cell.component()).map_err(invalid)? else {
            continue;
        };
        if descriptor.delivery != "current" {
            continue;
        }
        let event = control_event_from_value(row.event_json)?;
        if event.kind == arkret_wire::EventKind::ConflictRecovery {
            // Recovery writes retain the original cell's scope/target binding.
            // Missing imported origin metadata keeps detail unavailable; it is
            // not grounds to reject an otherwise valid governance recovery.
            continue;
        }
        let payload = serde_json::to_value(&event.payload).map_err(invalid)?;
        let (scope, target) =
            origin_binding(&realm_id, &cell, &event, &payload, &descriptor.target_class)?;
        let selector = CurrentSelector {
            scope_ref: scope,
            cell_id: cell_ref,
        };
        let scope_key = String::from_utf8(
            arkret_canonical::canonical_json_bytes(&selector.scope_ref).map_err(invalid)?,
        )
        .map_err(invalid)?;
        let event_id = crate::ids::parse_event_id(event.event_id.as_str())
            .ok_or_else(|| invalid("invalid accepted origin EventId"))?;
        let count = sql_query("INSERT INTO current_selector_origins(realm_id,cell_id,scope_key,selector,target,source_event_id) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(realm_id,cell_id,scope_key) DO UPDATE SET selector=current_selector_origins.selector WHERE current_selector_origins.selector=EXCLUDED.selector AND current_selector_origins.target=EXCLUDED.target")
            .bind::<Text,_>(realm).bind::<Text,_>(selector.cell_id.as_str()).bind::<Text,_>(&scope_key)
            .bind::<Jsonb,_>(serde_json::to_value(&selector).map_err(invalid)?).bind::<Jsonb,_>(serde_json::to_value(target).map_err(invalid)?)
            .bind::<Binary,_>(event_id.to_vec()).execute(&mut *conn).await?;
        if count != 1 {
            return Err(invalid(
                "accepted current selector origin conflicts with its immutable target",
            ));
        }
    }
    Ok(())
}

fn origin_binding(
    realm: &RealmId,
    cell: &CellId,
    event: &Event,
    payload: &Value,
    target_class: &str,
) -> Result<(ScopeRef, CurrentTarget), EventSealCommitError> {
    let mut scope = match &event.scope_ref {
        ScopeRef::RealmGenesis => ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        scope => scope.clone(),
    };
    if let Some(effective) = payload.get("effective_scope") {
        scope = serde_json::from_value(effective.clone()).map_err(invalid)?;
    }
    if cell.component() == "ak.component.circle.member.v1" {
        let circle = payload
            .get("circle_id")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("Circle member origin misses circle_id"))?;
        scope = ScopeRef::Circle {
            realm_id: realm.clone(),
            circle_id: CircleId::new(circle.to_owned()).map_err(invalid)?,
        };
    }
    let target = match target_class {
        "realm" => CurrentTarget::Realm,
        "member" => CurrentTarget::Member {
            actor_id: serde_json::from_value::<ActorId>(
                payload
                    .get("member_id")
                    .cloned()
                    .ok_or_else(|| invalid("Member current origin misses ActorId"))?,
            )
            .map_err(invalid)?,
        },
        "strand" => {
            let id = if cell.component() == "ak.component.strand.watch.v1" {
                payload
                    .get("strand_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("Strand watch origin misses StrandId"))?
            } else {
                cell.subject()
            };
            CurrentTarget::Strand {
                strand_id: StrandId::new(id.to_owned()).map_err(invalid)?,
            }
        }
        "pin_scope"
            if payload.pointer("/pin_scope/kind").and_then(Value::as_str) == Some("strand") =>
        {
            CurrentTarget::Strand {
                strand_id: StrandId::new(
                    payload
                        .pointer("/pin_scope/id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| invalid("Pin origin misses scope id"))?
                        .to_owned(),
                )
                .map_err(invalid)?,
            }
        }
        "pin_scope" => CurrentTarget::Realm,
        "object" if cell.subject().starts_with("ak:strand:") => CurrentTarget::Strand {
            strand_id: StrandId::new(cell.subject().to_owned()).map_err(invalid)?,
        },
        "object" if !cell.subject().starts_with("ak:message:") => CurrentTarget::Realm,
        "event" | "object" => CurrentTarget::Event {
            event_id: arkret_wire::EventId::new(format!(
                "ak:event:{}",
                cell.subject()
                    .rsplit(':')
                    .next()
                    .ok_or_else(|| invalid("Message subject misses token"))?
            ))
            .map_err(invalid)?,
        },
        _ => return Err(invalid("unknown current target class")),
    };
    Ok((scope, target))
}

async fn lifecycle_values(
    conn: &mut AsyncPgConnection,
    realm: &str,
    origins: &[OriginRow],
    cells: &BTreeMap<CellRef, CellState>,
) -> Result<BTreeMap<String, CellState>, EventSealCommitError> {
    let mut result = BTreeMap::new();
    let mut actors = BTreeMap::new();
    for origin in origins {
        let cell = CellRef::new(origin.cell_id.clone()).map_err(invalid)?;
        if CellId::from_ref(&cell).map_err(invalid)?.component() != "ak.component.agent.status.v1" {
            continue;
        }
        let Some(state) = cells.get(&cell) else {
            continue;
        };
        let token: [u8; 33] = origin
            .source_event_id
            .as_slice()
            .try_into()
            .map_err(invalid)?;
        let id = arkret_wire::EventId::new(crate::ids::format_event_id(&token)).map_err(invalid)?;
        let source = sql_query("SELECT event_json AS value FROM state_control_events WHERE realm_id=$1 AND event_digest=$2")
            .bind::<Text,_>(realm).bind::<Text,_>(id.event_digest().as_str()).get_result::<JsonRow>(&mut *conn).await.optional()?;
        let Some(source) = source else {
            continue;
        };
        let event = control_event_from_value(source.value)?;
        if event.kind != arkret_wire::EventKind::RealmCreate {
            continue;
        }
        let principal = event.actor_id.signing_principal_id().to_string();
        if actors
            .get(&principal)
            .is_some_and(|old| old != &event.actor_id)
        {
            return Err(invalid("Agent lifecycle origins disagree on full ActorId"));
        }
        actors.insert(principal.clone(), event.actor_id);
        result.insert(principal, state.clone());
    }
    Ok(result)
}

/// Missing required entries invalidate a derived publication, not admission.
pub(super) async fn baseline_missing(
    conn: &mut AsyncPgConnection,
    realm: &str,
) -> Result<bool, diesel::result::Error> {
    // A ready flag cannot substitute for the required baseline entries.
    let count = sql_query("SELECT COUNT(DISTINCT payload->'selector'->>'cell_id') AS value FROM current_result_heads WHERE realm_id=$1 AND target_kind='realm' AND payload->'selector'->'scope_ref'->>'kind'='realm' AND payload->'selector'->>'cell_id'=ANY($2)")
        .bind::<Text,_>(realm)
        .bind::<Array<Text>,_>(vec![
            "ak:cell:ak.component.realm.genesis.v1:null",
            "ak:cell:ak.component.realm.policy.v1:null",
            "ak:cell:ak.component.realm.policy_bundle.v1:null",
            "ak:cell:ak.component.realm.set_default_strand.v1:null",
        ])
        .get_result::<CountRow>(conn).await?.value;
    Ok(count != 4)
}

/// Retain typed Realm unavailability when a value cannot be materialized.
pub(super) async fn publish(
    conn: &mut AsyncPgConnection,
    realm: &str,
    cells: &BTreeMap<CellRef, CellState>,
    revision: i64,
    mv_heads: &CurrentMvHeads,
    mv_ready: bool,
) -> Result<(), EventSealCommitError> {
    let mut origins = sql_query("SELECT FALSE AS unwritten,cell_id,selector,target,source_event_id FROM current_selector_origins WHERE realm_id=$1 ORDER BY scope_key,cell_id")
        .bind::<Text,_>(realm).load::<OriginRow>(&mut *conn).await?;
    let lifecycles = lifecycle_values(conn, realm, &origins, cells).await?;
    let now = chrono::Utc::now();
    let mut next_expiry: Option<chrono::DateTime<chrono::Utc>> = None;
    let known = origins
        .iter()
        .map(|origin| origin.cell_id.clone())
        .collect::<BTreeSet<_>>();
    let realm_id = RealmId::new(realm.to_owned()).map_err(invalid)?;
    for descriptor in current_family_descriptors().map_err(invalid)? {
        if descriptor.delivery != "current"
            || !descriptor.singleton
            || descriptor.target_class != "realm"
        {
            continue;
        }
        let cell_id = format!("ak:cell:{}:null", descriptor.cell_family);
        if !known.contains(&cell_id) && !cells.keys().any(|cell| cell.as_str() == cell_id) {
            origins.push(OriginRow {
                unwritten: true,
                source_event_id: Vec::new(),
                cell_id: cell_id.clone(),
                selector: serde_json::json!({"scope_ref":{"kind":"realm","realm_id":realm_id},"cell_id":cell_id}),
                target: serde_json::json!({"kind":"realm"}),
            });
        }
    }
    let mut entries = Vec::new();
    let mut ready = mv_ready
        && cells
            .keys()
            .any(|cell| cell.as_str() == "ak:cell:ak.component.realm.genesis.v1:null");
    for cell in cells.keys() {
        let parsed = CellId::from_ref(cell).map_err(invalid)?;
        if current_family_descriptor(parsed.component())
            .map_err(invalid)?
            .is_some_and(|d| d.delivery == "current")
            && !known.contains(cell.as_str())
        {
            ready = false;
        }
    }
    for origin in origins {
        let selector: CurrentSelector = serde_json::from_value(origin.selector).map_err(invalid)?;
        let target: CurrentTarget = serde_json::from_value(origin.target).map_err(invalid)?;
        let family = selector.family().map_err(invalid)?;
        let Some(descriptor) = current_family_descriptor(&family).map_err(invalid)? else {
            ready = false;
            continue;
        };
        let cell_id = CellRef::new(origin.cell_id).map_err(invalid)?;
        let result = match cells.get(&cell_id) {
            None if origin.unwritten
                && matches!(descriptor.lattice.as_str(), "cas_register" | "fsm") =>
            {
                serde_json::json!({"status":"value","value":null})
            }
            None if origin.unwritten
                && descriptor.lattice == "or_set"
                && descriptor.result_projection == "joined_value" =>
            {
                serde_json::json!({"status":"value","value":[]})
            }
            None if origin.unwritten => {
                continue;
            }
            None => serde_json::json!({"status":"removed"}),
            Some(_) if descriptor.lattice == "mv_register" => {
                let Some(heads) = mv_heads.get(&cell_id).filter(|heads| !heads.is_empty()) else {
                    ready = false;
                    continue;
                };
                let mut result_heads = Vec::new();
                for head in heads {
                    let mut value = head.value.clone();
                    if let Some(object) = value.as_object_mut() {
                        for field in &descriptor.projection_omitted_fields {
                            object.remove(field);
                        }
                        if descriptor.materialized_id_from_subject {
                            object.insert(
                                "id".into(),
                                Value::String(
                                    CellId::from_ref(&cell_id)
                                        .map_err(invalid)?
                                        .subject()
                                        .to_owned(),
                                ),
                            );
                        }
                    }
                    result_heads.push(serde_json::json!({"event_id":head.event_id,"value":value}));
                }
                serde_json::json!({"status":"heads","heads":result_heads})
            }
            Some(CellState::Value(value)) if family == "ak.component.agent.key.v1" => {
                match agent_keys::fold(value, &lifecycles, now) {
                    Ok((result, expiry)) => {
                        if let Some(expiry) = expiry {
                            next_expiry = Some(next_expiry.map_or(expiry, |old| old.min(expiry)));
                        }
                        result
                    }
                    Err(_) => {
                        ready = false;
                        continue;
                    }
                }
            }
            Some(CellState::Bottom(_)) if family == "ak.component.agent.key.v1" => {
                serde_json::json!({"status":"unavailable","reason":"bottom"})
            }
            Some(_) if descriptor.result_projection == "domain_current" => {
                ready = false;
                continue;
            }
            Some(CellState::Bottom(_)) => {
                serde_json::json!({"status":"unavailable","reason":"bottom"})
            }
            Some(CellState::Value(value)) => {
                let mut value = value.clone();
                if descriptor.lattice == "or_set" {
                    let Some(items) = value.as_array() else {
                        ready = false;
                        continue;
                    };
                    let mut unique = BTreeMap::new();
                    for item in items {
                        let Some(value) = item.get("value") else {
                            ready = false;
                            continue;
                        };
                        unique.insert(
                            arkret_canonical::canonical_json_bytes(value).map_err(invalid)?,
                            value.clone(),
                        );
                    }
                    value = Value::Array(unique.into_values().collect());
                }
                serde_json::json!({"status":"value","value":value})
            }
        };
        let mut wire = serde_json::json!({"selector":selector,"target":target,"revision":revision,"result":result});
        if arkret_canonical::canonical_json_bytes(&wire).map_err(invalid)?.len()
            > arkret_models_collaboration::sync_frames::current_results::MAX_ATOMIC_CURRENT_ENTRY_CANONICAL_BYTES {
            wire["result"] = serde_json::json!({"status":"unavailable","reason":"limit_exceeded"});
        }
        match CurrentResultEntry::try_from_json(wire) {
            Ok(entry) => entries.push(entry),
            Err(_) => {
                ready = false;
            }
        }
    }
    crate::current_results::publish_entries(conn, &entries)
        .await
        .map_err(persistence_to_store)?;
    sql_query("INSERT INTO governance_current_ready(realm_id,ready,revision,next_expiry) VALUES($1,$2,$3,$4) ON CONFLICT(realm_id) DO UPDATE SET ready=EXCLUDED.ready,revision=EXCLUDED.revision,next_expiry=EXCLUDED.next_expiry")
        .bind::<Text,_>(realm).bind::<Bool,_>(ready).bind::<BigInt,_>(revision).bind::<Nullable<Timestamptz>,_>(next_expiry).execute(&mut *conn).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(byte: u8) -> CurrentMvHead {
        CurrentMvHead {
            event_id: arkret_wire::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [byte; 32],
            ),
            value: serde_json::json!({"source":byte}),
        }
    }

    #[test]
    fn mv_views_keep_concurrent_heads_and_drop_only_observed_replacements() {
        let cell =
            CellRef::new("ak:cell:ak.component.agent.selector_claim.v1:claim".to_owned()).unwrap();
        let a = head(1);
        let b = head(2);
        let view = |head: &CurrentMvHead, covered: Vec<String>| {
            (
                BTreeMap::from([(cell.clone(), vec![head.clone()])]),
                covered.into_iter().collect(),
            )
        };
        let first = view(&a, vec![a.event_id.event_digest().to_string()]);
        let concurrent = view(&b, vec![b.event_id.event_digest().to_string()]);
        assert_eq!(
            merge_mv_views(&[first.clone(), concurrent]).unwrap()[&cell].len(),
            2
        );
        let replacement = view(
            &b,
            vec![
                a.event_id.event_digest().to_string(),
                b.event_id.event_digest().to_string(),
            ],
        );
        let merged = merge_mv_views(&[first.clone(), replacement]).unwrap();
        assert_eq!(merged[&cell][0].event_id, b.event_id);
        assert_eq!(merged[&cell].len(), 1);
        let removed = (
            CurrentMvHeads::new(),
            BTreeSet::from([a.event_id.event_digest().to_string()]),
        );
        assert!(merge_mv_views(&[first, removed]).unwrap().is_empty());
    }

    #[test]
    fn same_mv_source_cannot_change_its_materialized_value() {
        let cell =
            CellRef::new("ak:cell:ak.component.agent.selector_claim.v1:claim".to_owned()).unwrap();
        let a = head(1);
        let mut bad = a.clone();
        bad.value = serde_json::json!({"source":99});
        let view = |head: CurrentMvHead| {
            (
                BTreeMap::from([(cell.clone(), vec![head])]),
                BTreeSet::new(),
            )
        };
        assert!(merge_mv_views(&[view(a), view(bad)]).is_err());
    }
}
