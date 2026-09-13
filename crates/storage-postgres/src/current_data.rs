//! Durable data-plane source values. A patch observes its declared source,
//! never the receiver's most recently materialized object.
mod domain_fold;
mod domain_publication;
#[cfg(test)]
mod postgres_tests;
mod publication;

use arkret_wire::cbs::{ProjectedCellWrite, ProjectedOp};
use arkret_wire::patch::Patch;
use diesel::sql_types::{Array, Binary, Bool, Jsonb, Text};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::Value;
use soland_storage::{PersistenceError, PersistenceResult};

#[derive(QueryableByName)]
struct SourceRow {
    #[diesel(sql_type = Jsonb)]
    source_value: Value,
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    causal_depth: i64,
}

#[derive(QueryableByName)]
struct PendingCausalCell {
    #[diesel(sql_type = Text)]
    scope_key: String,
    #[diesel(sql_type = Text)]
    cell_id: String,
}

#[derive(QueryableByName)]
struct WinnerEvent {
    #[diesel(sql_type = Binary)]
    event_id: Vec<u8>,
}

/// Re-select causal-register winners after source eligibility changes. Causal
/// depth is immutable source evidence; rebuilding only filters eligibility and
/// reapplies the registered `(depth, full EventId bytes)` order.
pub(crate) async fn rebuild_pending_causal_registers(
    conn: &mut AsyncPgConnection,
    realm_id: &str,
    limit: i64,
) -> PersistenceResult<usize> {
    let rows = sql_query(
        "SELECT scope_key,cell_id FROM current_data_pending WHERE realm_id=$1 ORDER BY scope_key,cell_id LIMIT $2 FOR UPDATE SKIP LOCKED",
    )
    .bind::<Text, _>(realm_id)
    .bind::<diesel::sql_types::BigInt, _>(limit.clamp(1, 4096))
    .load::<PendingCausalCell>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?
    .into_iter()
    .filter(|row| arkret_wire::is_registered_causal_register_cell(&row.cell_id))
    .collect::<Vec<_>>();
    if rows.is_empty() {
        return Ok(0);
    }

    let revision = crate::current_results::next_revision(conn).await?;
    let mut entries = Vec::with_capacity(rows.len());
    for row in &rows {
        let lock = format!("current-data:{realm_id}:{}:{}", row.scope_key, row.cell_id);
        sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind::<Text, _>(&lock)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;

        let winner = sql_query(
            "SELECT s.event_id FROM current_data_sources s JOIN canonical_events c ON c.id=s.event_id WHERE s.realm_id=$1 AND s.scope_key=$2 AND s.cell_id=$3 AND s.available AND c.state='accepted' AND EXISTS(SELECT 1 FROM accepted_events a WHERE a.id=s.event_id) ORDER BY s.causal_depth DESC,s.event_id DESC LIMIT 1",
        )
        .bind::<Text, _>(realm_id)
        .bind::<Text, _>(&row.scope_key)
        .bind::<Text, _>(&row.cell_id)
        .get_result::<WinnerEvent>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;

        let selector = arkret_models_collaboration::sync_frames::current_results::CurrentSelector {
            scope_ref: serde_json::from_str(&row.scope_key).map_err(projection_error)?,
            cell_id: arkret_wire::CellRef::new(row.cell_id.clone()).map_err(projection_error)?,
        };
        if let Some(winner) = winner {
            sql_query("INSERT INTO current_data_winners(realm_id,scope_key,cell_id,event_id) VALUES($1,$2,$3,$4) ON CONFLICT(realm_id,scope_key,cell_id) DO UPDATE SET event_id=EXCLUDED.event_id")
                .bind::<Text,_>(realm_id).bind::<Text,_>(&row.scope_key).bind::<Text,_>(&row.cell_id)
                .bind::<Binary,_>(winner.event_id).execute(&mut *conn).await
                .map_err(PersistenceError::database)?;
            entries.push(publication::materialized_current(conn, selector, revision).await?);
        } else {
            sql_query("DELETE FROM current_data_winners WHERE realm_id=$1 AND scope_key=$2 AND cell_id=$3")
                .bind::<Text,_>(realm_id).bind::<Text,_>(&row.scope_key).bind::<Text,_>(&row.cell_id)
                .execute(&mut *conn).await.map_err(PersistenceError::database)?;
            entries.push(publication::removed_current(selector, revision)?);
        }
        sql_query(
            "DELETE FROM current_data_pending WHERE realm_id=$1 AND scope_key=$2 AND cell_id=$3",
        )
        .bind::<Text, _>(realm_id)
        .bind::<Text, _>(&row.scope_key)
        .bind::<Text, _>(&row.cell_id)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    }
    crate::current_results::publish_entries(conn, &entries).await?;
    Ok(rows.len())
}

/// Publishes current Data sources in the ordinary Event transaction or the
/// exact committed command-unit transaction. Pending and rejected units cannot
/// publish even when a member has only Data writes.
pub(crate) async fn commit_sources(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    suite: arkret_canonical::DigestSuite,
) -> PersistenceResult<()> {
    let digest = event
        .event_digest_with_digest_suite(suite)
        .map_err(projection_error)?;
    #[derive(QueryableByName)]
    struct PublicationState {
        #[diesel(sql_type = Bool)]
        registered: bool,
        #[diesel(sql_type = Bool)]
        committed: bool,
    }
    let state = sql_query("SELECT EXISTS(SELECT 1 FROM state_control_events WHERE event_digest=$1) AS registered, EXISTS(SELECT 1 FROM state_seal_control_events b WHERE b.event_digest=$1 AND b.outcome='committed' AND NOT EXISTS(SELECT 1 FROM state_seal_quarantine q WHERE q.seal_id=b.seal_id)) AS committed")
        .bind::<Text, _>(&digest).get_result::<PublicationState>(&mut *conn).await.map_err(PersistenceError::database)?;
    if !data_sources_publishable(
        state.registered,
        state.committed,
        arkret_schema::classify_event_execution(event).map_err(projection_error)?,
    ) {
        return Ok(());
    }
    let Some(descriptor) = event.kind.descriptor() else {
        return Ok(());
    };
    let families = descriptor
        .cell_writes
        .iter()
        .filter_map(|write| {
            let family = write.cell_family?;
            if write.execution != Some(arkret_wire::EventCellExecution::Data) {
                return None;
            }
            match write.state_model?.as_str() {
                "causal_register" => Some((family.as_str(), true)),
                "or_set" => Some((family.as_str(), false)),
                _ => None,
            }
        })
        .collect::<Vec<_>>();
    if families.is_empty() {
        return Ok(());
    }
    let scope_key = String::from_utf8(
        arkret_canonical::canonical_json_bytes(&event.scope_ref).map_err(projection_error)?,
    )
    .map_err(projection_error)?;
    let causal = event
        .causal_refs
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let mut writes =
        arkret_schema::project_registered_cell_writes(event, suite).map_err(projection_error)?;
    let mut causal_cells = Vec::new();
    let mut domain_cells = Vec::new();
    let mut pending_current = false;
    writes.sort_by(|left, right| {
        left.cell_id
            .as_str()
            .as_bytes()
            .cmp(right.cell_id.as_str().as_bytes())
    });
    for write in writes {
        let Some((_, is_causal_register)) = families.iter().find(|(family, _)| {
            write
                .cell_id
                .as_str()
                .starts_with(&format!("ak:cell:{family}:"))
        }) else {
            continue;
        };
        let cell = arkret_wire::CellId::from_ref(&write.cell_id).map_err(projection_error)?;
        if arkret_models_collaboration::sync_frames::current_results::current_family_descriptor(
            cell.component(),
        )
        .map_err(projection_error)?
        .is_none_or(|descriptor| descriptor.delivery != "current")
        {
            continue;
        }
        let family =
            arkret_models_collaboration::sync_frames::current_results::current_family_descriptor(
                cell.component(),
            )
            .map_err(projection_error)?
            .ok_or_else(|| projection_error("missing current family"))?;
        let (target_kind, target_key) = match family.target_derivation.as_str() {
            "enclosing_realm" => ("realm", String::new()),
            "registered_subject_strand" => ("strand", cell.subject().to_owned()),
            "registered_position_subject_strand" => (
                "strand",
                cell.strand_position_target()
                    .map_err(projection_error)?
                    .to_string(),
            ),
            "message_create_event_from_registered_subject" => (
                "event",
                cell.subject()
                    .parse::<arkret_wire::MessageId>()
                    .map_err(projection_error)?
                    .event_id()
                    .to_string(),
            ),
            "accepted_object_subject_target" => {
                if let Ok(message) = cell.subject().parse::<arkret_wire::MessageId>() {
                    ("event", message.event_id().to_string())
                } else if let Ok(strand) = cell.subject().parse::<arkret_wire::StrandId>() {
                    ("strand", strand.to_string())
                } else {
                    ("realm", String::new())
                }
            }
            "accepted_pin_scope_target" => {
                let pin = serde_json::to_value(&event.payload).map_err(projection_error)?;
                let pin = pin
                    .get("pin_scope")
                    .ok_or_else(|| projection_error("missing accepted pin scope"))?;
                if pin.get("kind").and_then(Value::as_str) == Some("strand") {
                    (
                        "strand",
                        pin.get("id")
                            .and_then(Value::as_str)
                            .ok_or_else(|| projection_error("missing pin Strand"))?
                            .to_owned(),
                    )
                } else {
                    ("realm", String::new())
                }
            }
            _ => return Err(projection_error("unsupported Data target association")),
        };
        let lock = format!(
            "current-data:{}:{}:{}",
            event.realm_id, scope_key, write.cell_id
        );
        sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind::<Text, _>(&lock)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
        #[derive(QueryableByName)]
        struct TargetBinding {
            #[diesel(sql_type=Text)]
            target_kind: String,
            #[diesel(sql_type=Text)]
            target_key: String,
        }
        let existing=sql_query("SELECT target_kind,target_key FROM current_data_sources WHERE realm_id=$1 AND scope_key=$2 AND cell_id=$3 LIMIT 1")
            .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(&scope_key).bind::<Text,_>(write.cell_id.as_str())
            .get_result::<TargetBinding>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
        if existing
            .is_some_and(|old| old.target_kind != target_kind || old.target_key != target_key)
        {
            return Err(projection_error(
                "current selector target association changed",
            ));
        }
        let bases = sql_query("SELECT s.source_value,s.causal_depth FROM canonical_events e JOIN current_data_sources s ON e.id=s.event_id WHERE e.state='accepted' AND EXISTS(SELECT 1 FROM accepted_events accepted WHERE accepted.id=e.id) AND s.realm_id=$1 AND s.scope_key=$2 AND s.cell_id=$3 AND s.available AND s.event_digest=ANY($4) ORDER BY s.event_id FOR SHARE OF e,s")
            .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(&scope_key)
            .bind::<Text,_>(write.cell_id.as_str()).bind::<Array<Text>,_>(&causal)
            .load::<SourceRow>(&mut *conn).await.map_err(PersistenceError::database)?;
        #[derive(QueryableByName)]
        struct ExistingCount {
            #[diesel(sql_type=diesel::sql_types::BigInt)]
            count: i64,
        }
        let existing_count = sql_query("SELECT count(*)::bigint AS count FROM current_data_sources WHERE realm_id=$1 AND scope_key=$2 AND cell_id=$3")
            .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(&scope_key)
            .bind::<Text,_>(write.cell_id.as_str()).get_result::<ExistingCount>(&mut *conn).await
            .map_err(PersistenceError::database)?.count;
        if *is_causal_register
            && bases.is_empty()
            && (existing_count > 0 || matches!(&write.op, ProjectedOp::ApplyPatch { .. }))
        {
            if causal.is_empty() {
                return Err(projection_error(
                    "non-initial causal-register write declares no same-Cell source",
                ));
            }
            #[derive(QueryableByName)]
            struct Known {
                #[diesel(sql_type=diesel::sql_types::BigInt)]
                count: i64,
            }
            let known = sql_query("SELECT count(DISTINCT event_digest)::bigint AS count FROM current_data_sources s WHERE event_digest=ANY($1) AND available AND EXISTS(SELECT 1 FROM accepted_events e WHERE e.id=s.event_id)")
                .bind::<Array<Text>,_>(&causal).get_result::<Known>(&mut *conn).await
                .map_err(PersistenceError::database)?;
            if known.count as usize
                == causal
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
            {
                return Err(projection_error(
                    "patch sources belong to a different cell or effective scope",
                ));
            }
            return Err(PersistenceError::Conflict(
                "dependency_missing: exact accepted patch source is not materialized".into(),
            ));
        }
        let causal_depth = if bases.is_empty() {
            0
        } else {
            bases
                .iter()
                .map(|row| row.causal_depth)
                .max()
                .and_then(|depth| depth.checked_add(1))
                .filter(|depth| *depth <= 9_007_199_254_740_991)
                .ok_or_else(|| {
                    projection_error("causal depth exceeds the JSON-safe integer range")
                })?
        };
        let mut value = materialize_source(
            &write,
            &bases
                .into_iter()
                .map(|row| row.source_value)
                .collect::<Vec<_>>(),
        )?;
        // Persist exactly the complete value exposed by current. Authoring
        // digests must not depend on omitted projection-only fields.
        if let Some(object) = value.as_object_mut() {
            if family.materialized_id_from_subject {
                object.insert("id".into(), Value::String(cell.subject().to_owned()));
            }
            for omitted in &family.projection_omitted_fields {
                object.remove(omitted);
            }
        }
        sql_query("INSERT INTO current_data_sources(target_kind,target_key,realm_id,scope_key,cell_id,event_id,event_digest,source_value,causal_bases,causal_depth) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
            .bind::<Text,_>(target_kind).bind::<Text,_>(&target_key)
            .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(&scope_key)
            .bind::<Text,_>(write.cell_id.as_str()).bind::<Binary,_>(event.event_id.token_bytes().to_vec())
            .bind::<Text,_>(&digest).bind::<Jsonb,_>(value).bind::<Array<Text>,_>(&causal).bind::<diesel::sql_types::BigInt,_>(causal_depth)
            .execute(&mut *conn).await.map_err(PersistenceError::database)?;
        if *is_causal_register {
            sql_query("INSERT INTO current_data_winners(realm_id,scope_key,cell_id,event_id) VALUES($1,$2,$3,$4) ON CONFLICT(realm_id,scope_key,cell_id) DO UPDATE SET event_id=EXCLUDED.event_id WHERE EXISTS(SELECT 1 FROM current_data_sources candidate,current_data_sources incumbent WHERE candidate.realm_id=EXCLUDED.realm_id AND candidate.scope_key=EXCLUDED.scope_key AND candidate.cell_id=EXCLUDED.cell_id AND candidate.event_id=EXCLUDED.event_id AND incumbent.realm_id=current_data_winners.realm_id AND incumbent.scope_key=current_data_winners.scope_key AND incumbent.cell_id=current_data_winners.cell_id AND incumbent.event_id=current_data_winners.event_id AND (candidate.causal_depth>incumbent.causal_depth OR (candidate.causal_depth=incumbent.causal_depth AND candidate.event_id>incumbent.event_id)))")
                .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(&scope_key)
                .bind::<Text,_>(write.cell_id.as_str()).bind::<Binary,_>(event.event_id.token_bytes().to_vec())
                .execute(&mut *conn).await.map_err(PersistenceError::database)?;
            causal_cells.push(write.cell_id.clone());
        } else {
            if matches!(
                cell.component(),
                arkret_wire::CellFamilyId::PIN_V1 | arkret_wire::CellFamilyId::MESSAGE_REACTIONS_V1
            ) {
                domain_cells.push((
                    write.cell_id.clone(),
                    target_kind.to_owned(),
                    target_key.clone(),
                ));
            }
            pending_current = true;
            // Domain OR-set values need their registered server fold. Source
            // admission succeeds, but a missing fold cannot become a complete
            // empty current baseline.
            sql_query("INSERT INTO current_data_pending(realm_id,scope_key,cell_id,target_kind,target_key) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING")
                .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(&scope_key)
                .bind::<Text,_>(write.cell_id.as_str()).bind::<Text,_>(target_kind).bind::<Text,_>(&target_key).execute(&mut *conn).await
                .map_err(PersistenceError::database)?;
        }
    }
    if !causal_cells.is_empty() || !domain_cells.is_empty() {
        let revision = crate::current_results::next_revision(conn).await?;
        let mut entries = Vec::new();
        for cell_id in causal_cells {
            entries.push(
                publication::materialized_current(
                    conn,
                    arkret_models_collaboration::sync_frames::current_results::CurrentSelector {
                        scope_ref: event.scope_ref.clone(),
                        cell_id,
                    },
                    revision,
                )
                .await?,
            );
        }
        for (cell_id, target_kind, target_key) in domain_cells {
            let selector =
                arkret_models_collaboration::sync_frames::current_results::CurrentSelector {
                    scope_ref: event.scope_ref.clone(),
                    cell_id,
                };
            if let Some(entry) = domain_publication::materialize(
                conn,
                &selector,
                revision,
                &target_kind,
                &target_key,
                event.event_id.as_str(),
            )
            .await?
            {
                sql_query("DELETE FROM current_data_pending p WHERE realm_id=$1 AND scope_key=$2 AND cell_id=$3 AND NOT EXISTS(SELECT 1 FROM current_data_sources s WHERE s.realm_id=p.realm_id AND s.scope_key=p.scope_key AND s.cell_id=p.cell_id AND (NOT s.available OR NOT EXISTS(SELECT 1 FROM accepted_events e WHERE e.id=s.event_id))) AND NOT EXISTS(SELECT 1 FROM current_data_sources s JOIN current_data_dependencies d ON d.source_event_id=s.event_id WHERE s.realm_id=p.realm_id AND s.scope_key=p.scope_key AND s.cell_id=p.cell_id AND NOT EXISTS(SELECT 1 FROM accepted_events e WHERE e.id=d.ancestor_event_id))")
                    .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(&scope_key).bind::<Text,_>(selector.cell_id.as_str())
                    .execute(&mut *conn).await.map_err(PersistenceError::database)?;
                entries.push(entry);
            }
        }
        crate::current_results::publish_entries(conn, &entries).await?;
    } else if pending_current {
        // Even an unresolved domain fold participates in the current clock,
        // so a frozen authority/read transaction cannot observe half admission.
        crate::current_results::next_revision(conn).await?;
    }
    Ok(())
}

fn data_sources_publishable(
    registered_unit: bool,
    committed: bool,
    execution: Option<arkret_wire::CbsEffectPlane>,
) -> bool {
    if registered_unit {
        committed
    } else {
        execution == Some(arkret_wire::CbsEffectPlane::Data)
    }
}

fn projection_error(message: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("reducer_projection_failed: {message}"))
}

/// Resolve the registry-projected write against the one matching accepted
/// source selected by causal_refs. The caller reads that source in the same
/// transaction as admission and preserves its exact scope/cell association.
pub(crate) fn materialize_source(
    write: &ProjectedCellWrite,
    bases: &[Value],
) -> PersistenceResult<Value> {
    match &write.op {
        ProjectedOp::Direct(op) => op
            .value
            .clone()
            .ok_or_else(|| projection_error("data source has no complete value")),
        ProjectedOp::ApplyPatch {
            patch,
            expected_prestate,
        } => {
            // causal_refs records all explicitly observed sources. The signed
            // prestate digest selects the value used for computation, so merging
            // does not depend on receiver order or an implicit winner.
            let base = match (bases, expected_prestate) {
                ([base], None) => base,
                (_, Some(expected)) => {
                    let expected = expected
                        .as_str()
                        .ok_or_else(|| projection_error("patch prestate digest is not a string"))?;
                    let mut matching = bases.iter().filter(|base| {
                        arkret_canonical::canonical_json_bytes(base).is_ok_and(|bytes| {
                            arkret_canonical::verify_digest(&bytes, expected).is_ok()
                        })
                    });
                    let base = matching.next().ok_or_else(|| {
                        projection_error("patch prestate does not match an observed source")
                    })?;
                    if matching.any(|other| other != base) {
                        return Err(projection_error("ambiguous patch prestate"));
                    }
                    base
                }
                _ => {
                    return Err(projection_error(
                        "multiple patch sources require expected_state_digest",
                    ));
                }
            };
            let patch: Patch = serde_json::from_value(patch.clone()).map_err(projection_error)?;
            patch.apply(base).map_err(projection_error)
        }
        _ => Err(projection_error(
            "data source contains a control-plane-only projection",
        )),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn registered_data_member_waits_for_its_committed_unit() {
        use arkret_wire::CbsEffectPlane::{Control, Data};
        assert!(data_sources_publishable(false, false, Some(Data)));
        assert!(!data_sources_publishable(false, false, Some(Control)));
        for plane in [Some(Data), Some(Control)] {
            assert!(!data_sources_publishable(true, false, plane));
            assert!(data_sources_publishable(true, true, plane));
        }
    }

    fn update(patch: Value) -> ProjectedCellWrite {
        ProjectedCellWrite {
            cell_id: "ak:cell:ak.component.strand.object.v1:ak:strand:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .parse().unwrap(),
            op: ProjectedOp::ApplyPatch {
                patch,
                expected_prestate: None,
            },
        }
    }

    #[test]
    fn patch_refuses_missing_or_ambiguous_source() {
        let write = update(json!({"title":"next"}));
        assert!(materialize_source(&write, &[]).is_err());
        assert!(materialize_source(&write, &[json!({}), json!({})]).is_err());
    }

    #[test]
    fn concurrent_patches_materialize_from_their_shared_source() {
        let base = json!({"metadata":{"title":"base","summary":"original"}});
        let left = update(json!({"metadata.title":{"$op":"set","value":"left"}}));
        let right = update(json!({"metadata.summary":{"$op":"set","value":"right"}}));
        assert_eq!(
            materialize_source(&left, std::slice::from_ref(&base)).unwrap(),
            json!({"metadata":{"title":"left","summary":"original"}})
        );
        assert_eq!(
            materialize_source(&right, &[base]).unwrap(),
            json!({"metadata":{"title":"base","summary":"right"}})
        );
    }

    #[test]
    fn explicit_merge_selects_signed_prestate_independently_of_source_order() {
        let left = json!({"metadata":{"title":"left","summary":"original"}});
        let right = json!({"metadata":{"title":"base","summary":"right"}});
        let mut write = update(json!({"metadata.summary":{"$op":"set","value":"right"}}));
        if let ProjectedOp::ApplyPatch {
            expected_prestate, ..
        } = &mut write.op
        {
            *expected_prestate = Some(Value::String(arkret_canonical::sha256_digest(
                arkret_canonical::canonical_json_bytes(&left).unwrap(),
            )));
        }
        let expected = json!({"metadata":{"title":"left","summary":"right"}});
        assert_eq!(
            materialize_source(&write, &[left.clone(), right.clone()]).unwrap(),
            expected
        );
        assert_eq!(
            materialize_source(&write, &[right, left.clone()]).unwrap(),
            expected
        );
        assert!(materialize_source(&write, &[json!({"metadata":{"title":"other"}})]).is_err());
        assert_eq!(
            materialize_source(&write, &[left.clone(), left]).unwrap(),
            expected
        );
    }

    #[test]
    fn patch_digest_binds_the_source_before_modification() {
        let base = json!({"metadata":{"title":"base"}});
        let mut write = update(json!({"metadata.title":{"$op":"set","value":"next"}}));
        if let ProjectedOp::ApplyPatch {
            expected_prestate, ..
        } = &mut write.op
        {
            *expected_prestate = Some(Value::String(arkret_canonical::sha256_digest(
                arkret_canonical::canonical_json_bytes(&base).unwrap(),
            )));
        }
        assert!(materialize_source(&write, &[base]).is_ok());
        assert!(materialize_source(&write, &[json!({"metadata":{"title":"different"}})]).is_err());
    }
}
