//! Account summary publication at the accepted Seal transaction boundary.
use super::*;

#[derive(QueryableByName)]
struct SummaryMemberRow {
    #[diesel(sql_type = Text)]
    cell_id: String,
    #[diesel(sql_type = Text)]
    actor_key: String,
}

/// Invalidations precede every frontier mutation, including bare Seal imports
/// and collision quarantine. A later verified publication restores availability.
pub(super) async fn invalidate(
    conn: &mut AsyncPgConnection,
    realm: &str,
) -> Result<(), diesel::result::Error> {
    super::welcome_discovery::invalidate(conn, realm).await?;
    let revision = sql_query(
        "UPDATE account_summary_clock SET revision = revision + 1
        WHERE singleton RETURNING revision AS value",
    )
    .get_result::<CountRow>(&mut *conn)
    .await?
    .value;
    super::current_results::invalidate(conn, realm, revision).await?;
    sql_query(
        "UPDATE account_summary_versions v SET valid_until = $2
        FROM account_summary_current c WHERE c.realm_id = $1
          AND v.actor_key = c.actor_key AND v.realm_id = c.realm_id AND v.revision = c.revision",
    )
    .bind::<Text, _>(realm)
    .bind::<BigInt, _>(revision)
    .execute(&mut *conn)
    .await?;
    sql_query("INSERT INTO account_summary_versions
        (actor_key, realm_id, revision, activity_position, membership, title, default_strand_id, invalidated)
        SELECT c.actor_key, c.realm_id, $2, v.activity_position, c.membership, c.title, c.default_strand_id, TRUE
        FROM account_summary_current c JOIN account_summary_versions v
          ON v.actor_key = c.actor_key AND v.realm_id = c.realm_id AND v.revision = c.revision
        WHERE c.realm_id = $1")
        .bind::<Text, _>(realm).bind::<BigInt, _>(revision).execute(&mut *conn).await?;
    sql_query(
        "UPDATE account_summary_current SET available = FALSE, revision = $2 WHERE realm_id = $1",
    )
    .bind::<Text, _>(realm)
    .bind::<BigInt, _>(revision)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

pub(super) async fn register_delta_members(
    conn: &mut AsyncPgConnection,
    realm: &str,
    delta: &[String],
) -> Result<(), EventSealCommitError> {
    let rows = sql_query(
        "SELECT event_json AS value FROM state_control_events
        WHERE realm_id = $1 AND event_digest = ANY($2)",
    )
    .bind::<Text, _>(realm)
    .bind::<Array<Text>, _>(delta)
    .load::<JsonRow>(&mut *conn)
    .await?;
    for row in rows {
        let event = control_event_from_value(row.value)?;
        if event.kind != arkret_wire::EventKind::MemberState {
            continue;
        }
        let payload: arkret_models_collaboration::governance::membership_invite::MembershipPayload =
            serde_json::from_value(serde_json::to_value(&event.payload).map_err(serde_to_store)?)
                .map_err(serde_to_store)?;
        let actor_key = payload
            .member_id
            .canonical_key()
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        let subject = arkret_wire::composite_subject(&[actor_key.clone()])
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        let cell = arkret_wire::subject_cell(arkret_wire::CellFamilyId::MEMBER_STATE_V1, &subject);
        // Compare the immutable mapping on conflict instead of accepting a
        // different actor for a colliding composite subject.
        let count = sql_query(
            "INSERT INTO account_summary_members (realm_id, cell_id, actor_key)
            VALUES ($1, $2, $3) ON CONFLICT (realm_id, cell_id) DO UPDATE
            SET actor_key = account_summary_members.actor_key
            WHERE account_summary_members.actor_key = EXCLUDED.actor_key",
        )
        .bind::<Text, _>(realm)
        .bind::<Text, _>(&cell)
        .bind::<Text, _>(&actor_key)
        .execute(&mut *conn)
        .await?;
        if count != 1 {
            return Err(StoreError::Conflict(
                "account summary ActorId subject collision".to_owned(),
            )
            .into());
        }
    }
    super::current_results::register_delta_origins(conn, realm, delta).await?;
    Ok(())
}

fn singleton<'a>(
    cells: &'a BTreeMap<CellRef, ResolvedCellState>,
    family: &str,
) -> Option<&'a Value> {
    let cell = CellRef::new(format!("ak:cell:{family}:null")).ok()?;
    cells.get(&cell)?.settled_value()
}

fn visible_membership<'a>(
    cells: &'a BTreeMap<CellRef, ResolvedCellState>,
    cell: &CellRef,
    destroyed: bool,
) -> Option<&'a str> {
    if destroyed {
        return None;
    }
    cells
        .get(cell)?
        .settled_value()?
        .as_str()
        .filter(|state| matches!(*state, "join" | "knock"))
}

pub(super) async fn publish(
    conn: &mut AsyncPgConnection,
    realm: &str,
    cells: &BTreeMap<CellRef, ResolvedCellState>,
    causal_winners: &super::current_results::CurrentCausalWinners,
    causal_ready: bool,
) -> Result<(), EventSealCommitError> {
    super::welcome_discovery::publish(conn, realm, cells).await?;
    let rows = sql_query("SELECT cell_id, actor_key FROM account_summary_members WHERE realm_id = $1 ORDER BY actor_key")
        .bind::<Text, _>(realm).load::<SummaryMemberRow>(&mut *conn).await?;
    let title = singleton(cells, arkret_wire::CellFamilyId::REALM_PROFILE_V1)
        .and_then(|profile| profile.get("title"))
        .and_then(Value::as_str);
    let default_strand = singleton(
        cells,
        arkret_wire::CellFamilyId::REALM_SET_DEFAULT_STRAND_V1,
    )
    .and_then(Value::as_str);
    let destroyed = singleton(cells, arkret_wire::CellFamilyId::REALM_DESTROY_V1).is_some();
    let revision = sql_query(
        "UPDATE account_summary_clock SET revision = revision + 1
        WHERE singleton RETURNING revision AS value",
    )
    .get_result::<CountRow>(&mut *conn)
    .await?
    .value;
    for row in rows {
        let cell = CellRef::new(row.cell_id).map_err(|e| StoreError::Backend(e.to_string()))?;
        // Membership is a security-plane `sequenced_state` cell. Read the
        // model-independent settled value just like singleton summaries do;
        // matching only `ResolvedCellState::Value` silently hid every sealed
        // join from account-current and made newly created Realms disappear.
        let membership = visible_membership(cells, &cell, destroyed);
        let title = (membership == Some("join")).then_some(title).flatten();
        let default_strand = (membership == Some("join"))
            .then_some(default_strand)
            .flatten();
        sql_query(
            "UPDATE account_summary_versions SET valid_until = $3
            WHERE actor_key = $1 AND realm_id = $2 AND valid_until IS NULL",
        )
        .bind::<Text, _>(&row.actor_key)
        .bind::<Text, _>(realm)
        .bind::<BigInt, _>(revision)
        .execute(&mut *conn)
        .await?;
        sql_query("INSERT INTO account_summary_versions
            (actor_key, realm_id, revision, activity_position, membership, title, default_strand_id, invalidated)
            VALUES ($1, $2, $3, $3, $4, $5, $6, TRUE)")
            .bind::<Text, _>(&row.actor_key).bind::<Text, _>(realm).bind::<BigInt, _>(revision)
            .bind::<Nullable<Text>, _>(membership).bind::<Nullable<Text>, _>(title)
            .bind::<Nullable<Text>, _>(default_strand).execute(&mut *conn).await?;
        sql_query(
            "INSERT INTO account_summary_current
            (actor_key, realm_id, revision, membership, title, default_strand_id, available)
            VALUES ($1, $2, $3, $4, $5, $6, TRUE)
            ON CONFLICT (actor_key, realm_id) DO UPDATE SET revision = EXCLUDED.revision,
              membership = EXCLUDED.membership, title = EXCLUDED.title,
              default_strand_id = EXCLUDED.default_strand_id, available = TRUE",
        )
        .bind::<Text, _>(&row.actor_key)
        .bind::<Text, _>(realm)
        .bind::<BigInt, _>(revision)
        .bind::<Nullable<Text>, _>(membership)
        .bind::<Nullable<Text>, _>(title)
        .bind::<Nullable<Text>, _>(default_strand)
        .execute(&mut *conn)
        .await?;
    }
    super::current_results::publish(conn, realm, cells, revision, causal_winners, causal_ready)
        .await?;
    Ok(())
}

/// A concurrent branch checkpoint is not the current Realm result. Join the
/// union of the current leaves using the same SDK batch reducer as acceptance.
pub(super) async fn publish_current_frontier(
    conn: &mut AsyncPgConnection,
    realm: &str,
    registry: &dyn CellStateRegistry,
) -> Result<(), EventSealCommitError> {
    let leaves = sql_query(
        "SELECT parent.id AS value FROM state_seals parent
        WHERE parent.realm_id = $1
          AND NOT EXISTS (SELECT 1 FROM state_seal_quarantine q WHERE q.seal_id = parent.id)
          AND NOT EXISTS (SELECT 1 FROM state_seals child WHERE child.realm_id = $1
            AND child.predecessor_ref = parent.id
            AND NOT EXISTS (SELECT 1 FROM state_seal_quarantine q WHERE q.seal_id = child.id))",
    )
    .bind::<Text, _>(realm)
    .load::<TextRow>(&mut *conn)
    .await?;
    let single_leaf = leaves.len() == 1;
    if leaves.is_empty() || super::realm_has_seal_collision(conn, realm).await? {
        return Ok(());
    }
    let realm_id =
        RealmId::new(realm.to_owned()).map_err(|e| StoreError::Backend(e.to_string()))?;
    let rule_context = CheckpointRuleContext::capture(registry, &realm_id)?;
    let mut covered = BTreeSet::new();
    let mut causal_views = Vec::new();
    let causal_ready = true;
    let mut expected_seal = None;
    for leaf in leaves {
        let row = sql_query(
            "SELECT realm_id, covered_event_digests, covered_seal_ids, state_json
            FROM state_seal_effective_checkpoints WHERE seal_id = $1",
        )
        .bind::<Text, _>(&leaf.value)
        .get_result::<EffectiveStateCheckpointRow>(&mut *conn)
        .await
        .optional()?;
        let Some(row) = row else {
            return Ok(());
        };
        if row.realm_id != realm || !row.covered_seal_ids.contains(&leaf.value) {
            return Err(
                StoreError::Backend("invalid current summary checkpoint".to_owned()).into(),
            );
        }
        let view = checkpoint_view_from_value(row.state_json)?;
        let reusable = view.rule_context.reusable_with(&rule_context);
        let quarantined = sql_query(
            "SELECT COUNT(*) AS value FROM state_seal_quarantine WHERE seal_id = ANY($1)",
        )
        .bind::<Array<Text>, _>(&row.covered_seal_ids)
        .get_result::<CountRow>(&mut *conn)
        .await?
        .value;
        if quarantined != 0 {
            return Ok(());
        }
        if single_leaf && reusable && view.causal_ready {
            return publish(
                conn,
                realm,
                &view.cells,
                &view.causal_winners,
                view.causal_ready,
            )
            .await;
        }
        let heads = if reusable && view.causal_ready {
            view.causal_winners
        } else {
            let Some(heads) = super::current_results::rebuild_causal_winners(
                conn,
                realm,
                &row.covered_seal_ids,
                &row.covered_event_digests,
                &rule_context,
            )
            .await?
            else {
                return Ok(());
            };
            heads
        };
        if single_leaf {
            let seal =
                sql_query("SELECT seal_json AS value FROM state_seals WHERE id=$1 AND realm_id=$2")
                    .bind::<Text, _>(&leaf.value)
                    .bind::<Text, _>(realm)
                    .get_result::<JsonRow>(&mut *conn)
                    .await?;
            expected_seal =
                Some(serde_json::from_value::<Seal>(seal.value).map_err(serde_to_store)?);
        }
        causal_views.push((heads, row.covered_event_digests.iter().cloned().collect()));
        covered.extend(row.covered_event_digests);
    }
    let covered = covered.into_iter().collect::<Vec<_>>();
    // Checkpoint coverage names Events by digest; `state_cell_ops` names them by
    // their typed EventId. Selecting on the digests directly matches nothing and
    // would rebuild the frontier from an empty cell set.
    let covered_event_ids = covered
        .iter()
        .map(|digest| {
            let digest = Hash::new(digest.clone())
                .map_err(|e| EventSealCommitError::from(StoreError::Backend(e.to_string())))?;
            EventId::from_event_digest(&digest)
                .map(|event_id| event_id.to_string())
                .map_err(|e| EventSealCommitError::from(StoreError::Backend(e.to_string())))
        })
        .collect::<Result<Vec<_>, EventSealCommitError>>()?;
    let rows = sql_query(
        "SELECT op.cell_id, op.seal_id, op.op_json FROM state_cell_ops op
        WHERE op.realm_id = $1 AND op.event_id = ANY($2)
          AND EXISTS (SELECT 1 FROM state_seals s WHERE s.id = op.seal_id)
          AND NOT EXISTS (SELECT 1 FROM state_seal_quarantine q WHERE q.seal_id = op.seal_id)
        ORDER BY op.cell_id, op.seq",
    )
    .bind::<Text, _>(realm)
    .bind::<Array<Text>, _>(&covered_event_ids)
    .load::<EventCellOpRow>(&mut *conn)
    .await?;
    let mut batches = BTreeMap::<CellRef, Vec<(String, Vec<IssuedOp>)>>::new();
    for row in rows {
        let cell = CellRef::new(row.cell_id).map_err(|e| StoreError::Backend(e.to_string()))?;
        let issued = sealed_op_from_value(row.op_json)?;
        let batches = batches.entry(cell).or_default();
        if let Some((seal, ops)) = batches.last_mut()
            && seal == &row.seal_id
        {
            ops.push(issued);
        } else {
            batches.push((row.seal_id, vec![issued]));
        }
    }
    let realm_id =
        RealmId::new(realm.to_owned()).map_err(|e| StoreError::Backend(e.to_string()))?;
    let mut cells = BTreeMap::new();
    let mut security_cells = BTreeMap::new();
    for (cell, batches) in batches {
        let binding = registry.resolve(&realm_id, &cell)?;
        let batches = batches.into_iter().map(|(_, ops)| ops).collect::<Vec<_>>();
        let resolved =
            arkret_state::join_cell_seal_batches(binding.model.as_ref(), &cell, &batches)
                .map_err(|error| StoreError::Backend(format!("cell state resolution: {error}")))?;
        if binding.execution == arkret_wire::EventCellExecution::Security {
            if !matches!(resolved, ResolvedCellState::Sequenced(_)) {
                return Err(StoreError::Backend(format!(
                    "security cell {cell} did not resolve to sequenced state"
                ))
                .into());
            }
            security_cells.insert(cell.clone(), resolved.clone());
        }
        cells.insert(cell.clone(), resolved);
    }
    let causal_winners = super::current_results::merge_causal_winner_views(&causal_views)?;
    if let Some(seal) = expected_seal {
        let root = compute_state_root(
            arkret_state::GovernanceView::new(&security_cells),
            seal.state_root
                .digest_suite()
                .map_err(|error| StoreError::Backend(error.to_string()))?,
        )
        .map_err(|error| StoreError::Backend(error.to_string()))?;
        if root != seal.state_root {
            return Err(StoreError::Conflict(
                "rebuilt current state disagrees with accepted Seal root".into(),
            )
            .into());
        }
    }
    publish(conn, realm, &cells, &causal_winners, causal_ready).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member_cell() -> CellRef {
        CellRef::new("ak:cell:ak.component.member.state.v1:test".to_owned()).unwrap()
    }

    #[test]
    fn sequenced_membership_is_visible_and_terminal_states_fail_closed() {
        let cell = member_cell();
        let event_id = arkret_wire::EventId::new(
            "ak:event:Aa6iDufaFu2o2ofTO5hEnIl2HBA8OUnXes2kHEWgLlTs".to_owned(),
        )
        .unwrap();
        let mut cells = BTreeMap::from([(
            cell.clone(),
            ResolvedCellState::Sequenced(arkret_state::SequencedStateValue {
                revision_event_id: event_id,
                value: Value::String("join".to_owned()),
            }),
        )]);

        assert_eq!(visible_membership(&cells, &cell, false), Some("join"));
        assert_eq!(visible_membership(&cells, &cell, true), None);

        cells.insert(
            cell.clone(),
            ResolvedCellState::Value(Value::String("leave".to_owned())),
        );
        assert_eq!(visible_membership(&cells, &cell, false), None);
    }
}
