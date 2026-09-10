//! Publish the winning MLS chain beside the accepted Seal/current projection.
use arkret_models_crypto::{MlsCommitPayload, MlsEpochHead};

use super::*;

fn invalid(message: impl std::fmt::Display) -> diesel::result::Error {
    diesel::result::Error::DeserializationError(Box::new(std::io::Error::other(
        message.to_string(),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn transition_event(
        conn: &mut AsyncPgConnection,
        scope: &arkret_wire::ScopeRef,
        sequence: u64,
        payload: Value,
        kind: &str,
    ) -> Event {
        let event = arkret_wire::test_support::raw_event(
            kind,
            scope.clone(),
            arkret_wire::DidCoreId::new("ak:did_core:webvh:alice.example").unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:webvh:station.example").unwrap(),
            sequence,
            arkret_wire::Hlc::new(format!("019f00000000-{sequence:04x}-aabbccdd")).unwrap(),
            payload,
        )
        .unwrap();
        let id = crate::ids::parse_event_id(event.event_id.as_str()).unwrap();
        sql_query("INSERT INTO canonical_events(id,digest_suite,digest,actor_id,actor_seq,realm_id,kind,schema_id,canonical_bytes,envelope) VALUES($1,1,$2,'author',$3,$4,$5,'test',$6,$7)")
            .bind::<Binary,_>(id.to_vec()).bind::<Binary,_>(id[1..].to_vec()).bind::<BigInt,_>(sequence as i64)
            .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(kind).bind::<Binary,_>(serde_json::to_vec(&event).unwrap())
            .bind::<Jsonb,_>(serde_json::to_value(&event).unwrap()).execute(conn).await.unwrap();
        event
    }

    #[tokio::test]
    async fn welcome_chain_replaces_same_epoch_branch_and_restores_quarantined_suffix() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let mut conn = pg_conn(&pool).await.unwrap();
        let realm = RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap();
        let scope = arkret_wire::ScopeRef::Realm {
            realm_id: realm.clone(),
        };
        let group = scope.canonical_mls_group_id().unwrap();
        let binding = |epoch| {
            arkret_models_crypto::MlsGovernanceBindingPayload::realm(
                realm.clone(),
                group.clone(),
                0,
                epoch,
                Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
                arkret_wire::ContentScheme::MlsRfc9420,
                None,
                arkret_wire::ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1,
                "ak.reducer.core.v1",
            )
            .unwrap()
        };
        let genesis_payload: arkret_models_collaboration::events_payloads::MlsGenesisPayload = serde_json::from_value(serde_json::json!({
            "mls_group_id":group,"effective_scope":scope,"epoch":0,"cipher_suite":"MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            "group_info_ref":format!("ak:blob:sha256:{}","a".repeat(64)),"ratchet_tree_ref":format!("ak:blob:sha256:{}","b".repeat(64)),
            "governance_binding":binding(0),"created_at":"2026-09-10T00:00:00.000Z"
        })).unwrap();
        let genesis = transition_event(
            &mut conn,
            &scope,
            71,
            serde_json::to_value(&genesis_payload).unwrap(),
            "ak.mls.genesis",
        )
        .await;
        let mut heads = Vec::new();
        for (sequence, bytes) in [(72, "YQ"), (73, "Yg")] {
            let payload: MlsCommitPayload = serde_json::from_value(serde_json::json!({
                "mls_group_id":group,"base_epoch":0,"base_epoch_ref":genesis.event_id,"proposal_refs":[],"next_epoch":1,
                "commit_bytes_b64":bytes,"governance_binding":binding(1)
            })).unwrap();
            let event = transition_event(
                &mut conn,
                &scope,
                sequence,
                serde_json::to_value(&payload).unwrap(),
                "ak.mls.commit",
            )
            .await;
            heads.push(MlsEpochHead {
                transition_ref: event.event_id.clone(),
                transition_event_digest: event.event_id.event_digest(),
                mls_transition_digest: payload.commit_digest().clone(),
                effective_scope: scope.clone(),
                mls_group_id: arkret_wire::Base64UrlString::new(group.clone()).unwrap(),
                previous_epoch: 0,
                next_epoch: 1,
                content_scheme: arkret_wire::ContentScheme::MlsRfc9420,
            });
        }
        let cell = arkret_state::mls_cells::mls_epoch_cell_id(&scope, &group).unwrap();
        let cells = |head: &MlsEpochHead| {
            BTreeMap::from([(
                cell.clone(),
                CellState::Value(serde_json::to_value(head).unwrap()),
            )])
        };
        publish(
            &mut conn,
            realm.as_str(),
            &cells(&heads[0]),
            &Default::default(),
        )
        .await
        .unwrap();
        publish(
            &mut conn,
            realm.as_str(),
            &cells(&heads[1]),
            &Default::default(),
        )
        .await
        .unwrap();
        let id = crate::ids::parse_event_id(heads[1].transition_ref.as_str()).unwrap();
        sql_query("UPDATE canonical_events SET state='quarantined' WHERE id=$1")
            .bind::<Binary, _>(id.to_vec())
            .execute(&mut *conn)
            .await
            .unwrap();
        let prefix = sql_query("SELECT count(*) AS value FROM mls_welcome_discovery_chain")
            .get_result::<CountRow>(&mut *conn)
            .await
            .unwrap();
        assert_eq!(prefix.value, 1);
        sql_query("UPDATE canonical_events SET state='accepted' WHERE id=$1")
            .bind::<Binary, _>(id.to_vec())
            .execute(&mut *conn)
            .await
            .unwrap();
        publish(
            &mut conn,
            realm.as_str(),
            &cells(&heads[1]),
            &Default::default(),
        )
        .await
        .unwrap();
        let restored = sql_query("SELECT head FROM mls_welcome_discovery_scopes WHERE available")
            .get_result::<DiscoveryHeadRow>(&mut *conn)
            .await
            .unwrap();
        assert_eq!(
            restored.head,
            Some(serde_json::to_value(&heads[1]).unwrap())
        );
        let count = sql_query("SELECT count(*) AS value FROM mls_welcome_discovery_chain")
            .get_result::<CountRow>(&mut *conn)
            .await
            .unwrap();
        assert_eq!(count.value, 2);
    }

    #[tokio::test]
    async fn membership_revision_tracks_cas_identity_and_not_unrelated_publication() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let mut conn = pg_conn(&pool).await.unwrap();
        let cell = CellRef::new("ak:cell:ak.component.member.state.v1:alice").unwrap();
        let cells = BTreeMap::from([(cell.clone(), CellState::Value(serde_json::json!("join")))]);
        let head = |marker: char| {
            serde_json::from_value::<Vec<arkret_state::lattice::cas_register::CasHead>>(
                serde_json::json!([
                    {"move_id":format!("sha256:{}",marker.to_string().repeat(64)),"value":"join"}
                ]),
            )
            .unwrap()
        };
        let mut heads = arkret_state::CasHeadsByCell::from([(cell.clone(), head('a'))]);
        publish(&mut conn, "realm", &cells, &heads).await.unwrap();
        invalidate(&mut conn, "realm").await.unwrap();
        publish(&mut conn, "realm", &cells, &heads).await.unwrap();
        let revision = sql_query("SELECT revision AS value FROM mls_welcome_discovery_membership")
            .get_result::<CountRow>(&mut conn)
            .await
            .unwrap()
            .value;
        assert_eq!(revision, 1);
        heads.insert(cell.clone(), head('b'));
        publish(&mut conn, "realm", &cells, &heads).await.unwrap();
        let revision = sql_query("SELECT revision AS value FROM mls_welcome_discovery_membership")
            .get_result::<CountRow>(&mut conn)
            .await
            .unwrap()
            .value;
        assert_eq!(
            revision, 2,
            "equal join values with different sources are distinct incarnations"
        );
        heads.insert(cell, head('a'));
        publish(&mut conn, "realm", &cells, &heads).await.unwrap();
        let revision = sql_query("SELECT revision AS value FROM mls_welcome_discovery_membership")
            .get_result::<CountRow>(&mut conn)
            .await
            .unwrap()
            .value;
        assert_eq!(
            revision, 3,
            "returning to an existing branch still invalidates the old window"
        );
    }
}

#[derive(QueryableByName)]
struct DiscoveryHeadRow {
    #[diesel(sql_type = Nullable<Jsonb>)]
    head: Option<Value>,
}

#[derive(QueryableByName)]
struct DiscoveryEventRow {
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
}
async fn event_at(
    conn: &mut AsyncPgConnection,
    event_ref: &str,
) -> Result<Option<DiscoveryEventRow>, diesel::result::Error> {
    let id =
        crate::ids::parse_event_id(event_ref).ok_or_else(|| invalid("malformed MLS Event ref"))?;
    sql_query("SELECT envelope FROM accepted_events WHERE id=$1")
        .bind::<Binary, _>(id.to_vec())
        .get_result::<DiscoveryEventRow>(conn)
        .await
        .optional()
}

pub(super) async fn invalidate(
    conn: &mut AsyncPgConnection,
    realm: &str,
) -> Result<(), diesel::result::Error> {
    sql_query("UPDATE mls_welcome_discovery_membership SET available=FALSE WHERE realm_id=$1")
        .bind::<Text, _>(realm)
        .execute(&mut *conn)
        .await?;
    sql_query("UPDATE mls_welcome_discovery_scopes SET available=FALSE WHERE realm_id=$1")
        .bind::<Text, _>(realm)
        .execute(conn)
        .await?;
    Ok(())
}

pub(super) async fn publish(
    conn: &mut AsyncPgConnection,
    realm: &str,
    cells: &BTreeMap<CellRef, CellState>,
    cas_heads: &arkret_state::CasHeadsByCell,
) -> Result<(), diesel::result::Error> {
    for (cell, state) in cells {
        if !(cell
            .as_str()
            .starts_with("ak:cell:ak.component.member.state.v1:")
            || cell
                .as_str()
                .starts_with("ak:cell:ak.component.circle.member.v1:"))
        {
            continue;
        }
        let (value, available) = match state {
            CellState::Value(value) => (Some(value), true),
            CellState::Bottom(_) => (None, false),
        };
        let heads = cas_heads.get(cell).map(Vec::as_slice).unwrap_or_default();
        let available = available && heads.len() == 1;
        let heads = serde_json::to_value(heads).map_err(invalid)?;
        sql_query("INSERT INTO mls_welcome_discovery_membership(realm_id,cell_id,current_value,available,cas_heads) VALUES($1,$2,$3,$4,$5) ON CONFLICT(realm_id,cell_id) DO UPDATE SET current_value=EXCLUDED.current_value,available=EXCLUDED.available,cas_heads=EXCLUDED.cas_heads,revision=mls_welcome_discovery_membership.revision+CASE WHEN mls_welcome_discovery_membership.current_value IS DISTINCT FROM EXCLUDED.current_value OR mls_welcome_discovery_membership.cas_heads IS DISTINCT FROM EXCLUDED.cas_heads THEN 1 ELSE 0 END")
            .bind::<Text,_>(realm).bind::<Text,_>(cell.as_str()).bind::<Nullable<Jsonb>,_>(value).bind::<Bool,_>(available).bind::<Jsonb,_>(heads).execute(&mut *conn).await?;
    }
    // Unresolved or absent epoch cells remain unavailable. Other Seal changes
    // do not increment the MLS eligibility revision when the head is unchanged.
    for (cell, value) in cells {
        if !cell
            .as_str()
            .starts_with("ak:cell:ak.component.mls.epoch.v1:")
        {
            continue;
        }
        let CellState::Value(value) = value else {
            continue;
        };
        let current: MlsEpochHead = serde_json::from_value(value.clone()).map_err(invalid)?;
        current.validate().map_err(invalid)?;
        let expected_cell = arkret_state::mls_cells::mls_epoch_cell_id(
            &current.effective_scope,
            current.mls_group_id.as_str(),
        )
        .map_err(invalid)?;
        if &expected_cell != cell
            || current.effective_scope.realm_id_opt().map(|id| id.as_str()) != Some(realm)
        {
            return Err(invalid(
                "accepted MLS epoch index has inconsistent coordinates",
            ));
        }
        let scope = serde_json::to_value(&current.effective_scope).map_err(invalid)?;
        let group = current.mls_group_id.as_str();
        sql_query("INSERT INTO mls_welcome_discovery_scopes(scope,group_id,realm_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING")
            .bind::<Jsonb,_>(&scope).bind::<Text,_>(group).bind::<Text,_>(realm).execute(&mut *conn).await?;
        let previous = sql_query("SELECT head FROM mls_welcome_discovery_scopes WHERE scope=$1 AND group_id=$2 FOR UPDATE")
            .bind::<Jsonb,_>(&scope).bind::<Text,_>(group).get_result::<DiscoveryHeadRow>(&mut *conn).await?;
        if previous.head.as_ref() != Some(value) {
            let mut head = current.clone();
            loop {
                let known = sql_query("SELECT EXISTS(SELECT 1 FROM mls_welcome_discovery_chain WHERE scope=$1 AND group_id=$2 AND epoch=$3 AND event_ref=$4) AS present")
                    .bind::<Jsonb,_>(&scope).bind::<Text,_>(group).bind::<BigInt,_>(i64::try_from(head.next_epoch).map_err(invalid)?)
                    .bind::<Text,_>(head.transition_ref.as_str()).get_result::<crate::ExistsRow>(&mut *conn).await?.present;
                if known {
                    break;
                }
                let event = event_at(conn, head.transition_ref.as_str()).await;
                let event = match event {
                    Ok(Some(record)) => {
                        serde_json::from_value::<Event>(record.envelope).map_err(invalid)?
                    }
                    Ok(None) => {
                        return Err(invalid("accepted MLS chain predecessor is unavailable"));
                    }
                    Err(error) => return Err(invalid(error)),
                };
                let (binding, digest, predecessor) = match event.kind {
                    arkret_wire::EventKind::MlsGenesis => {
                        let payload: arkret_models_collaboration::events_payloads::MlsGenesisPayload = serde_json::from_value(serde_json::to_value(&event.payload).map_err(invalid)?).map_err(invalid)?;
                        let digest = payload.transition_digest().map_err(invalid)?;
                        (payload.governance_binding, digest, None)
                    }
                    arkret_wire::EventKind::MlsCommit => {
                        let payload: MlsCommitPayload = serde_json::from_value(
                            serde_json::to_value(&event.payload).map_err(invalid)?,
                        )
                        .map_err(invalid)?;
                        (
                            payload.governance_binding().clone(),
                            payload.commit_digest().clone(),
                            Some(
                                arkret_wire::EventId::new(payload.base_epoch_ref().to_owned())
                                    .map_err(invalid)?,
                            ),
                        )
                    }
                    _ => {
                        return Err(invalid(
                            "accepted MLS chain contains a non-transition Event",
                        ));
                    }
                };
                if event.event_id != head.transition_ref
                    || event.event_id.event_digest() != head.transition_event_digest
                    || digest != head.mls_transition_digest
                    || binding.effective_scope() != &current.effective_scope
                    || binding.mls_group_id() != group
                    || binding.next_epoch() != head.next_epoch
                    || binding.previous_epoch() != head.previous_epoch
                    || binding.content_scheme() != current.content_scheme
                {
                    return Err(invalid("accepted MLS transition differs from indexed head"));
                }
                sql_query("UPDATE mls_welcome_discovery_entries e SET eligible=FALSE FROM mls_welcome_discovery_chain c WHERE c.scope=$1 AND c.group_id=$2 AND c.epoch=$3 AND e.scope=c.scope AND e.group_id=c.group_id AND e.commit_ref=c.event_ref")
                    .bind::<Jsonb,_>(&scope).bind::<Text,_>(group).bind::<BigInt,_>(i64::try_from(head.next_epoch).map_err(invalid)?)
                    .execute(&mut *conn).await?;
                sql_query("INSERT INTO mls_welcome_discovery_chain(scope,group_id,epoch,event_ref) VALUES($1,$2,$3,$4) ON CONFLICT(scope,group_id,epoch) DO UPDATE SET event_ref=EXCLUDED.event_ref")
                    .bind::<Jsonb,_>(&scope).bind::<Text,_>(group).bind::<BigInt,_>(i64::try_from(head.next_epoch).map_err(invalid)?)
                    .bind::<Text,_>(event.event_id.as_str()).execute(&mut *conn).await?;
                sql_query("UPDATE mls_welcome_discovery_entries e SET eligible=(EXISTS(SELECT 1 FROM accepted_events a JOIN peer_keypackage_claims p ON p.source_id=e.claim_source AND p.claim_request_id=e.claim_request WHERE a.pk=e.event_pk AND p.state IN ('claimed','last_resort_claimed') AND p.outcome->'claim_receipt'=a.envelope#>'{payload,claim_receipt}' AND p.outcome#>>'{claims,0,claim_id}'=e.claim_id)) WHERE e.scope=$1 AND e.group_id=$2 AND e.commit_ref=$3")
                    .bind::<Jsonb,_>(&scope).bind::<Text,_>(group).bind::<Text,_>(event.event_id.as_str()).execute(&mut *conn).await?;
                let Some(previous_ref) = predecessor else {
                    break;
                };
                let record = event_at(conn, previous_ref.as_str())
                    .await
                    .map_err(invalid)?
                    .ok_or_else(|| invalid("accepted MLS predecessor is missing"))?;
                let previous_event: Event =
                    serde_json::from_value(record.envelope).map_err(invalid)?;
                // The transition's own binding supplies the preceding epoch;
                // the next loop verifies all remaining coordinates and digest.
                let payload = serde_json::to_value(&previous_event.payload).map_err(invalid)?;
                let (binding, digest) = if previous_event.kind == arkret_wire::EventKind::MlsGenesis
                {
                    let p: arkret_models_collaboration::events_payloads::MlsGenesisPayload =
                        serde_json::from_value(payload).map_err(invalid)?;
                    let d = p.transition_digest().map_err(invalid)?;
                    (p.governance_binding, d)
                } else {
                    let p: MlsCommitPayload = serde_json::from_value(payload).map_err(invalid)?;
                    (p.governance_binding().clone(), p.commit_digest().clone())
                };
                if binding.next_epoch() != head.previous_epoch
                    || binding.next_epoch() >= head.next_epoch
                {
                    return Err(invalid("MLS predecessor epoch does not strictly decrease"));
                }
                head = MlsEpochHead {
                    transition_ref: previous_ref.clone(),
                    transition_event_digest: previous_ref.event_digest(),
                    mls_transition_digest: digest,
                    effective_scope: binding.effective_scope().clone(),
                    mls_group_id: current.mls_group_id.clone(),
                    previous_epoch: binding.previous_epoch(),
                    next_epoch: binding.next_epoch(),
                    content_scheme: binding.content_scheme(),
                };
            }
            sql_query("WITH removed AS (DELETE FROM mls_welcome_discovery_chain WHERE scope=$1 AND group_id=$2 AND epoch>$3 RETURNING event_ref) UPDATE mls_welcome_discovery_entries SET eligible=FALSE WHERE scope=$1 AND group_id=$2 AND commit_ref IN (SELECT event_ref FROM removed)")
                .bind::<Jsonb,_>(&scope).bind::<Text,_>(group).bind::<BigInt,_>(i64::try_from(current.next_epoch).map_err(invalid)?).execute(&mut *conn).await?;
            sql_query("UPDATE mls_welcome_discovery_scopes SET revision=revision+1,head=$3 WHERE scope=$1 AND group_id=$2")
                .bind::<Jsonb,_>(&scope).bind::<Text,_>(group).bind::<Jsonb,_>(value).execute(&mut *conn).await?;
        }
        sql_query(
            "UPDATE mls_welcome_discovery_scopes SET available=TRUE WHERE scope=$1 AND group_id=$2",
        )
        .bind::<Jsonb, _>(&scope)
        .bind::<Text, _>(group)
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}
