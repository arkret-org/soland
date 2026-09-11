//! Durable data-plane source values. A patch observes its declared source,
//! never the receiver's most recently materialized object.
mod domain_fold;
mod domain_publication;
#[cfg(test)]
mod postgres_tests;
mod publication;

use arkret_wire::cbs::{ProjectedCellWrite, ProjectedOp};
use arkret_wire::patch::Patch;
use diesel::sql_types::{Array, Binary, Jsonb, Text};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::Value;
use soland_storage::{PersistenceError, PersistenceResult};

#[derive(QueryableByName)]
struct SourceRow {
    #[diesel(sql_type = Jsonb)]
    source_value: Value,
}

/// Runs inside EventCommitUnitOfWork after the accepted canonical row exists.
/// Only non-log data cells are admitted here; sealed governance cells have a
/// separate publication boundary.
pub(crate) async fn commit_sources(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    suite: arkret_canonical::DigestSuite,
) -> PersistenceResult<()> {
    if !event.kind.is_data_plane() {
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
            match write.lattice?.as_str() {
                "mv_register" => Some((family.as_str(), true)),
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
    let digest = event
        .event_digest_with_digest_suite(suite)
        .map_err(projection_error)?
        .to_string();
    let causal = event
        .causal_refs
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let mut writes =
        arkret_schema::project_registered_cell_writes(event, suite).map_err(projection_error)?;
    let mut mv_cells = Vec::new();
    let mut domain_cells = Vec::new();
    let mut pending_current = false;
    writes.sort_by(|left, right| {
        left.cell_id
            .as_str()
            .as_bytes()
            .cmp(right.cell_id.as_str().as_bytes())
    });
    for write in writes {
        let Some((_, is_mv)) = families.iter().find(|(family, _)| {
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
        let bases = sql_query("SELECT s.source_value FROM canonical_events e JOIN current_data_sources s ON e.id=s.event_id WHERE e.state='accepted' AND EXISTS(SELECT 1 FROM accepted_events accepted WHERE accepted.id=e.id) AND s.realm_id=$1 AND s.scope_key=$2 AND s.cell_id=$3 AND s.available AND s.event_digest=ANY($4) ORDER BY s.event_id FOR SHARE OF e,s")
            .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(&scope_key)
            .bind::<Text,_>(write.cell_id.as_str()).bind::<Array<Text>,_>(&causal)
            .load::<SourceRow>(&mut *conn).await.map_err(PersistenceError::database)?;
        if bases.is_empty() && matches!(&write.op, ProjectedOp::ApplyPatch { .. }) {
            if causal.is_empty() {
                return Err(projection_error("patch declares no causal source"));
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
        sql_query("INSERT INTO current_data_sources(realm_id,scope_key,cell_id,event_id,event_digest,source_value,causal_bases,target_kind,target_key) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)")
            .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(&scope_key)
            .bind::<Text,_>(write.cell_id.as_str()).bind::<Binary,_>(event.event_id.token_bytes().to_vec())
            .bind::<Text,_>(&digest).bind::<Jsonb,_>(value).bind::<Array<Text>,_>(&causal).bind::<Text,_>(target_kind).bind::<Text,_>(&target_key)
            .execute(&mut *conn).await.map_err(PersistenceError::database)?;
        if *is_mv {
            sql_query("DELETE FROM current_data_heads h USING current_data_sources s WHERE h.realm_id=$1 AND h.scope_key=$2 AND h.cell_id=$3 AND s.realm_id=h.realm_id AND s.scope_key=h.scope_key AND s.cell_id=h.cell_id AND s.event_id=h.event_id AND s.event_digest=ANY($4)")
                .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(&scope_key)
                .bind::<Text,_>(write.cell_id.as_str()).bind::<Array<Text>,_>(&causal)
                .execute(&mut *conn).await.map_err(PersistenceError::database)?;
            sql_query("INSERT INTO current_data_heads(realm_id,scope_key,cell_id,event_id) VALUES($1,$2,$3,$4)")
                .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(&scope_key)
                .bind::<Text,_>(write.cell_id.as_str()).bind::<Binary,_>(event.event_id.token_bytes().to_vec())
                .execute(&mut *conn).await.map_err(PersistenceError::database)?;
            mv_cells.push(write.cell_id.clone());
        } else {
            if matches!(
                cell.component(),
                "ak.component.pin.v1" | "ak.component.message.reactions.v1"
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
    if !mv_cells.is_empty() || !domain_cells.is_empty() {
        let revision = crate::current_results::next_revision(conn).await?;
        let mut entries = Vec::new();
        for cell_id in mv_cells {
            entries.push(
                publication::materialized_heads(
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
