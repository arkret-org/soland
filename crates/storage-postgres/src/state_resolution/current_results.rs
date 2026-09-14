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
pub(super) struct CurrentCausalWinner {
    event_id: arkret_wire::EventId,
    depth: u64,
    value: Value,
}

pub(super) type CurrentCausalWinners = BTreeMap<CellRef, CurrentCausalWinner>;

/// Merge deterministic winners from parent views under one eligibility context.
pub(super) fn merge_causal_winner_views(
    views: &[(CurrentCausalWinners, BTreeSet<String>)],
) -> StoreResult<CurrentCausalWinners> {
    let mut result = CurrentCausalWinners::new();
    for (winners, _) in views {
        for (cell, candidate) in winners {
            if let Some(old) = result.get(cell) {
                if old.event_id == candidate.event_id
                    && (old.value != candidate.value || old.depth != candidate.depth)
                {
                    return Err(StoreError::Backend(
                        "same causal source has inconsistent value or depth".into(),
                    ));
                }
                if (old.depth, old.event_id.token_bytes())
                    >= (candidate.depth, candidate.event_id.token_bytes())
                {
                    continue;
                }
            }
            result.insert(cell.clone(), candidate.clone());
        }
    }
    Ok(result)
}

pub(super) async fn advance_causal_winners(
    conn: &mut AsyncPgConnection,
    realm: &str,
    predecessors: &[String],
    new_rows: &[(i64, String, String, Value)],
    rule_context: &CheckpointRuleContext,
) -> Result<(CurrentCausalWinners, bool), EventSealCommitError> {
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
        let heads = if view.rule_context.reusable_with(rule_context) && view.causal_ready {
            view.causal_winners
        } else {
            let Some(heads) = rebuild_causal_winners(
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
    let mut winners = merge_causal_winner_views(&views)?;
    let mut updates = BTreeMap::<CellRef, Vec<arkret_state::StateWrite>>::new();
    for (_, cell, _, value) in new_rows {
        let cell = CellRef::new(cell.clone()).map_err(invalid)?;
        let parsed = CellId::from_ref(&cell).map_err(invalid)?;
        if !current_family_descriptor(parsed.component())
            .map_err(invalid)?
            .is_some_and(|d| d.state_model == "causal_register")
        {
            continue;
        }
        let issued = sealed_op_from_value(value.clone())?;
        updates.entry(cell).or_default().push(issued.op);
    }
    for (cell, mut writes) in updates {
        if let Some(current) = winners.get(&cell) {
            writes.push(
                arkret_state::StateWrite::new(
                    current.event_id.clone(),
                    arkret_wire::LatticeOp {
                        op_type: arkret_wire::LatticeOpType::Set,
                        value: Some(current.value.clone()),
                        ..arkret_wire::LatticeOp::empty()
                    },
                )
                .with_fixed_depth(current.depth),
            );
        }
        match arkret_state::causal_register_state(&writes) {
            Ok(state) => {
                winners.insert(
                    cell,
                    CurrentCausalWinner {
                        event_id: state.winner.event_id,
                        depth: state.winner.depth,
                        value: state.winner.value,
                    },
                );
            }
            Err(_) => ready = false,
        }
    }
    Ok((winners, ready))
}

#[derive(QueryableByName)]
struct CausalRebuildSeal {
    #[diesel(sql_type = Text)]
    seal_id: String,
    #[diesel(sql_type = Array<Text>)]
    covered_seal_ids: Vec<String>,
    #[diesel(sql_type = Array<Text>)]
    parents: Vec<String>,
}

/// Reconstruct fixed same-Cell depths from signed causal predecessors, never
/// from Seal ancestry, arrival order, or a previously projected winner.
pub(super) async fn rebuild_causal_winners(
    conn: &mut AsyncPgConnection,
    realm: &str,
    closure: &[String],
    covered: &[String],
    context: &CheckpointRuleContext,
) -> Result<Option<CurrentCausalWinners>, EventSealCommitError> {
    if !matches!(context, CheckpointRuleContext::Stable { .. }) {
        return Ok(None);
    }
    let seals = sql_query("SELECT s.id AS seal_id,c.covered_seal_ids,ARRAY_REMOVE(ARRAY[s.predecessor_ref], NULL) AS parents FROM state_seals s JOIN state_seal_effective_checkpoints c ON c.seal_id=s.id AND c.realm_id=s.realm_id WHERE s.realm_id=$1 AND s.id=ANY($2) AND NOT EXISTS(SELECT 1 FROM state_seal_quarantine q WHERE q.seal_id=s.id)")
        .bind::<Text,_>(realm).bind::<Array<Text>,_>(closure).load::<CausalRebuildSeal>(&mut *conn).await?;
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
    let mut writes = BTreeMap::<CellRef, Vec<arkret_state::StateWrite>>::new();
    for row in rows {
        let cell = CellRef::new(row.cell_id).map_err(invalid)?;
        if !current_family_descriptor(CellId::from_ref(&cell).map_err(invalid)?.component())
            .map_err(invalid)?
            .is_some_and(|d| d.state_model == "causal_register")
        {
            continue;
        }
        let issued = sealed_op_from_value(row.op_json)?;
        writes.entry(cell).or_default().push(issued.op);
    }
    let mut result = CurrentCausalWinners::new();
    for (cell, candidates) in writes {
        let state = match arkret_state::causal_register_state(&candidates) {
            Ok(state) => state,
            Err(_) => return Ok(None),
        };
        result.insert(
            cell,
            CurrentCausalWinner {
                event_id: state.winner.event_id,
                depth: state.winner.depth,
                value: state.winner.value,
            },
        );
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
    let rows = sql_query("SELECT DISTINCT op.cell_id,e.event_json FROM state_cell_ops op JOIN state_control_events e ON e.realm_id=op.realm_id AND e.event_digest=op.event_id WHERE op.realm_id=$1 AND op.event_id=ANY($2)")
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
    if cell.component() == arkret_wire::CellFamilyId::CIRCLE_MEMBER_V1 {
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
        "member" if event.kind == arkret_wire::EventKind::InviteAccept => CurrentTarget::Member {
            // The registered invite-accept member effect targets the signing Account.
            actor_id: event.actor_id.clone(),
        },
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
            let id = if cell.component() == arkret_wire::CellFamilyId::STRAND_WATCH_V1 {
                payload
                    .get("strand_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("Strand watch origin misses StrandId"))?
                    .to_owned()
            } else if cell.component() == arkret_wire::CellFamilyId::STRAND_POSITION_V1 {
                cell.strand_position_target().map_err(invalid)?.to_string()
            } else {
                cell.subject().to_owned()
            };
            CurrentTarget::Strand {
                strand_id: StrandId::new(id).map_err(invalid)?,
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
    cells: &BTreeMap<CellRef, ResolvedCellState>,
) -> Result<BTreeMap<String, ResolvedCellState>, EventSealCommitError> {
    let mut result = BTreeMap::new();
    let mut actors = BTreeMap::new();
    for origin in origins {
        let cell = CellRef::new(origin.cell_id.clone()).map_err(invalid)?;
        if CellId::from_ref(&cell).map_err(invalid)?.component()
            != arkret_wire::CellFamilyId::AGENT_STATUS_V1
        {
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
    cells: &BTreeMap<CellRef, ResolvedCellState>,
    revision: i64,
    causal_winners: &CurrentCausalWinners,
    causal_ready: bool,
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
    let mut ready = causal_ready
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
            None if origin.unwritten && descriptor.state_model == "sequenced_state" => {
                serde_json::json!({"status":"value","value":null})
            }
            None if origin.unwritten
                && descriptor.state_model == "or_set"
                && descriptor.result_projection == "joined_value" =>
            {
                serde_json::json!({"status":"value","value":[]})
            }
            None if origin.unwritten => {
                continue;
            }
            None => serde_json::json!({"status":"removed"}),
            Some(_) if descriptor.state_model == "causal_register" => {
                let Some(winner) = causal_winners.get(&cell_id) else {
                    ready = false;
                    continue;
                };
                let mut value = winner.value.clone();
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
                serde_json::json!({"status":"value","value":value,"source":{"event_id":winner.event_id,"depth":winner.depth}})
            }
            Some(state) if family == arkret_wire::CellFamilyId::AGENT_KEY_V1 => {
                let Some(value) = state.settled_value() else {
                    ready = false;
                    continue;
                };
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
            Some(_) if descriptor.result_projection == "domain_current" => {
                ready = false;
                continue;
            }
            Some(ResolvedCellState::Bottom(_)) => {
                ready = false;
                continue;
            }
            Some(state) => {
                let Some(value) = state.settled_value() else {
                    ready = false;
                    continue;
                };
                let mut value = value.clone();
                if descriptor.state_model == "or_set" {
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

    fn move_event(realm: &RealmId) -> Event {
        let actor = ActorId::account(arkret_wire::AccountId::new(
            "ak:did_core:web:current.example".parse().unwrap(),
            "ak:did_core:web:station.example".parse().unwrap(),
        ));
        arkret_wire::test_support::raw_event_for_actor_at(
            "ak.strand.move",
            ScopeRef::Realm {
                realm_id: realm.clone(),
            },
            actor,
            1,
            "000000000001-0000-00000000".parse().unwrap(),
            serde_json::json!({}),
            chrono::DateTime::parse_from_rfc3339("2026-09-14T00:00:00.000Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        )
        .unwrap()
    }

    fn head(byte: u8) -> CurrentCausalWinner {
        CurrentCausalWinner {
            event_id: arkret_wire::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [byte; 32],
            ),
            depth: 0,
            value: serde_json::json!({"source":byte}),
        }
    }

    #[test]
    fn causal_views_select_the_highest_fixed_rank() {
        let cell =
            CellRef::new("ak:cell:ak.component.agent.selector_claim.v1:claim".to_owned()).unwrap();
        let a = head(1);
        let b = head(2);
        let view = |head: &CurrentCausalWinner, covered: Vec<String>| {
            (
                BTreeMap::from([(cell.clone(), head.clone())]),
                covered.into_iter().collect(),
            )
        };
        let first = view(&a, vec![a.event_id.event_digest().to_string()]);
        let concurrent = view(&b, vec![b.event_id.event_digest().to_string()]);
        assert_eq!(
            merge_causal_winner_views(&[first.clone(), concurrent]).unwrap()[&cell].event_id,
            b.event_id
        );
        let replacement = view(
            &b,
            vec![
                a.event_id.event_digest().to_string(),
                b.event_id.event_digest().to_string(),
            ],
        );
        let merged = merge_causal_winner_views(&[first.clone(), replacement]).unwrap();
        assert_eq!(merged[&cell].event_id, b.event_id);
        let removed = (
            CurrentCausalWinners::new(),
            BTreeSet::from([a.event_id.event_digest().to_string()]),
        );
        assert!(
            merge_causal_winner_views(&[first, removed])
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn same_causal_source_cannot_change_its_materialized_value() {
        let cell =
            CellRef::new("ak:cell:ak.component.agent.selector_claim.v1:claim".to_owned()).unwrap();
        let a = head(1);
        let mut bad = a.clone();
        bad.value = serde_json::json!({"source":99});
        let view =
            |head: CurrentCausalWinner| (BTreeMap::from([(cell.clone(), head)]), BTreeSet::new());
        assert!(merge_causal_winner_views(&[view(a), view(bad)]).is_err());
    }

    #[test]
    fn strand_position_origin_uses_the_typed_pair_strand_component() {
        let realm = RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            arkret_canonical::sha256_bytes(b"typed pair current target"),
        ));
        let event = move_event(&realm);
        let board = "ak:space:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo";
        let strand = "ak:strand:AR0yYaLgfEhMOjzAp9eFpdYOf2dma-COBObvEGjj8NN0";
        let cell_text = format!("ak:cell:ak.component.strand.position.v1:{board}:{strand}");
        let cell = CellId::parse(&cell_text).unwrap();
        let payload = serde_json::to_value(&event.payload).unwrap();

        let (_, target) = origin_binding(&realm, &cell, &event, &payload, "strand").unwrap();
        assert_eq!(
            target,
            CurrentTarget::Strand {
                strand_id: StrandId::new(strand.to_owned()).unwrap(),
            }
        );

        let malformed_text =
            format!("ak:cell:ak.component.strand.position.v1:ak:space:bad:{strand}");
        let malformed = CellId::parse(&malformed_text).unwrap();
        assert!(origin_binding(&realm, &malformed, &event, &payload, "strand").is_err());
    }
}
