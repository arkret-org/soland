//! Bounded current-result windows. Never replays source Events to serve a page.
#[cfg(test)]
mod tests;
use arkret_models_collaboration::sync_frames::current_results::{
    CurrentCoverage, CurrentMemberCoverage, CurrentOutcome, CurrentSelector, CurrentTarget,
};
use arkret_models_collaboration::sync_frames::demand_sync::RealmDetailBaseline;
use arkret_wire::{CellRef, ScopeRef};
use soland_storage::{
    CurrentDetailOutcome, CurrentDetailPage, CurrentDetailPhase, CurrentDetailProgress,
    CurrentDetailRequest,
};

use super::*;
use crate::current_results::read::{Position, Selection};

#[derive(QueryableByName)]
struct Authority {
    #[diesel(sql_type=BigInt)]
    revision: i64,
    #[diesel(sql_type=sql_types::Bool)]
    ready: bool,
    #[diesel(sql_type=Nullable<Text>)]
    default_strand_id: Option<String>,
}

async fn read_authority(
    conn: &mut crate::AsyncPgConnection,
    actor: &str,
    realm: &str,
) -> Result<Option<Authority>, crate::PgTransactionError> {
    Ok(sql_query("SELECT COALESCE(r.revision,0) AS revision,(c.available AND COALESCE(r.ready,FALSE) AND (r.next_expiry IS NULL OR r.next_expiry>clock_timestamp())) AS ready,c.default_strand_id FROM account_summary_current c LEFT JOIN governance_current_ready r USING(realm_id) WHERE c.actor_key=$1 AND c.realm_id=$2 AND c.membership='join'")
        .bind::<Text,_>(actor).bind::<Text,_>(realm).get_result::<Authority>(&mut *conn).await.optional()?)
}

fn error(value: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::SchemaViolation(value.to_string())
}

fn priorities(request: &CurrentDetailRequest) -> PersistenceResult<Vec<String>> {
    let scope_ref = ScopeRef::Realm {
        realm_id: request.realm_id.clone(),
    };
    let cells = [
        "ak.component.realm.genesis.v1",
        "ak.component.realm.policy.v1",
        "ak.component.realm.policy_bundle.v1",
        "ak.component.realm.set_default_strand.v1",
    ]
    .into_iter()
    .map(|family| format!("ak:cell:{family}:null"))
    .collect::<Vec<_>>();
    cells
        .into_iter()
        .map(|cell| {
            CurrentSelector {
                scope_ref: scope_ref.clone(),
                cell_id: CellRef::new(cell).map_err(error)?,
            }
            .canonical_key()
            .map_err(error)
        })
        .collect()
}

async fn scope_visible(
    conn: &mut crate::AsyncPgConnection,
    actor: &str,
    request: &CurrentDetailRequest,
    scope: &ScopeRef,
) -> PersistenceResult<bool> {
    match scope {
        ScopeRef::Realm { realm_id } => Ok(realm_id == &request.realm_id),
        ScopeRef::Circle {
            realm_id,
            circle_id,
        } if realm_id == &request.realm_id => {
            // Membership's tuple subject is not reversible; use its exact
            // persisted target association, never a directory visibility flag.
            #[derive(QueryableByName)]
            struct Visible {
                #[diesel(sql_type=sql_types::Bool)]
                visible: bool,
            }
            let scope = serde_json::to_value(ScopeRef::Circle {
                realm_id: realm_id.clone(),
                circle_id: circle_id.clone(),
            })
            .map_err(error)?;
            Ok(sql_query("SELECT EXISTS(SELECT 1 FROM current_result_heads WHERE realm_id=$1 AND target_kind='member' AND target_key=$2 AND payload->'selector'->'scope_ref'=$3 AND payload->'selector'->>'cell_id' LIKE 'ak:cell:ak.component.circle.member.v1:%' AND payload->'result'->>'status'='value' AND payload->'result'->'value'='\"join\"'::jsonb) AS visible")
                .bind::<Text,_>(realm_id.as_str()).bind::<Text,_>(actor).bind::<Jsonb,_>(scope)
                .get_result::<Visible>(&mut *conn).await.map_err(PersistenceError::database)?.visible)
        }
        _ => Ok(false),
    }
}

pub(super) async fn page(
    pool: &PgPool,
    request: &CurrentDetailRequest,
    progress: Option<&CurrentDetailProgress>,
    byte_budget: usize,
    registry: &dyn arkret_state::state::CellRegistry,
) -> PersistenceResult<CurrentDetailOutcome> {
    if request
        .strand_ids
        .as_ref()
        .is_some_and(|items| items.len() > 32)
        || request.event_ids.len() > 100
    {
        return Err(error("current coverage exceeds the registered bound"));
    }
    let actor = request.actor_id.canonical_key().map_err(error)?;
    let request_digest = arkret_canonical::sha256_digest(
        arkret_canonical::canonical_json_bytes(request).map_err(error)?,
    );
    let genesis =
        CellRef::new("ak:cell:ak.component.realm.genesis.v1:null".to_owned()).map_err(error)?;
    registry
        .resolve(&request.realm_id, &genesis)
        .map_err(error)?;
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_,crate::PgTransactionError,_>(async |conn| {
        // All callers take retention before a clock lock. A clock share lock
        // keeps the verified authority generation stable while building a page.
        if let Some(progress)=progress {
            retention::check(conn,Some(progress.retained_revision),None).await?;
        } else { retention::lock(conn,true).await?; }
        crate::state_resolution::refresh_current_if_expired(conn,request.realm_id.as_str(),registry).await?;
        let cut=if progress.is_some() {
            sql_query("SELECT revision FROM account_summary_clock WHERE singleton FOR SHARE")
                .get_result::<SummaryWatermarkRow>(&mut *conn).await?.revision
        } else { retention::freeze_on_connection(conn).await?.0 };
        let Some(authority)=read_authority(conn,&actor,request.realm_id.as_str()).await? else { return Ok(CurrentDetailOutcome::NotFound); };
        if !authority.ready { return Ok(CurrentDetailOutcome::Unavailable); }
        let now=Utc::now().timestamp_millis();
        let mut progress=if let Some(progress)=progress {
            if progress.request_digest!=request_digest || progress.authority_revision!=authority.revision || (progress.phase!=CurrentDetailPhase::Live && progress.expires_at_ms<=now) {
                return Ok(CurrentDetailOutcome::Unavailable);
            }
            progress.clone()
        } else {
            let mut strands=match &request.strand_ids {
                Some(strands)=>strands.clone(),
                None=>authority.default_strand_id.as_ref().map(|id|id.parse()).transpose().map_err(error)?.into_iter().collect(),
            };
            strands.sort(); strands.dedup();
            let mut events=request.event_ids.clone(); events.sort(); events.dedup();
            CurrentDetailProgress {
                request_digest:request_digest.clone(),
                snapshot_cursor:arkret_wire::Cursor::new(format!("ak:cursor:{}",uuid::Uuid::now_v7().simple())).map_err(error)?,
                cut_revision:cut,authority_revision:authority.revision,retained_revision:cut,
                expires_at_ms:now+3_600_000,
                coverage:CurrentCoverage {realm:true,strand_ids:strands,members:if request.all_members {CurrentMemberCoverage::All} else {CurrentMemberCoverage::Selected {actor_ids:vec![]}},event_ids:events},
                phase:CurrentDetailPhase::Priority,scan_revision:0,scan_selector:String::new(),
            }
        };
        let was_baseline=progress.phase!=CurrentDetailPhase::Live;
        progress.coverage.validate().map_err(error)?;
        let mut priority=priorities(request)?;
        if was_baseline {
            #[derive(QueryableByName)]
            struct StrandSelector { #[diesel(sql_type=Jsonb)] selector:Value }
            for strand in &progress.coverage.strand_ids {
                let rows=sql_query("SELECT payload->'selector' AS selector FROM current_result_versions WHERE realm_id=$1 AND target_kind='strand' AND target_key=$2 AND payload->'selector'->>'cell_id'=$3 AND revision<=$4 AND (valid_until IS NULL OR valid_until>$4) ORDER BY selector_key LIMIT 2")
                    .bind::<Text,_>(request.realm_id.as_str()).bind::<Text,_>(strand.as_str())
                    .bind::<Text,_>(format!("ak:cell:ak.component.strand.object.v1:{strand}"))
                    .bind::<BigInt,_>(progress.cut_revision).load::<StrandSelector>(&mut *conn).await?;
                let [row]=rows.as_slice() else { return Ok(CurrentDetailOutcome::Unavailable); };
                let selector:CurrentSelector=serde_json::from_value(row.selector.clone()).map_err(error)?;
                if !scope_visible(conn,&actor,request,&selector.scope_ref).await? { return Ok(CurrentDetailOutcome::NotFound); }
                priority.push(selector.canonical_key().map_err(error)?);
            }
        }
        if was_baseline {
            #[derive(QueryableByName)]
            struct Count { #[diesel(sql_type=BigInt)] count:i64 }
            let count=sql_query("SELECT count(*)::bigint AS count FROM current_result_versions WHERE realm_id=$1 AND selector_key=ANY($2) AND revision<=$3 AND (valid_until IS NULL OR valid_until>$3)")
                .bind::<Text,_>(request.realm_id.as_str()).bind::<sql_types::Array<Text>,_>(&priority)
                .bind::<BigInt,_>(progress.cut_revision).get_result::<Count>(&mut *conn).await?;
            if count.count as usize!=priority.len() { return Ok(CurrentDetailOutcome::Unavailable); }
        }
        let strands=progress.coverage.strand_ids.iter().map(ToString::to_string).collect::<Vec<_>>();
        let events=progress.coverage.event_ids.iter().map(ToString::to_string).collect::<Vec<_>>();
        let (all_members,actors)=match &progress.coverage.members {
            CurrentMemberCoverage::All=>(true,vec![]),
            CurrentMemberCoverage::Selected {actor_ids}=>(false,actor_ids.iter().map(|actor|actor.canonical_key().map_err(error)).collect::<PersistenceResult<Vec<_>>>()?),
        };
        #[derive(QueryableByName)]
        struct Pending { #[diesel(sql_type=sql_types::Bool)] pending:bool }
        let pending=sql_query("SELECT EXISTS(SELECT 1 FROM current_data_pending WHERE realm_id=$1 AND ((target_kind='realm' AND $2) OR (target_kind='strand' AND target_key=ANY($3)) OR (target_kind='member' AND ($4 OR target_key=ANY($5))) OR (target_kind='event' AND target_key=ANY($6)))) AS pending")
            .bind::<Text,_>(request.realm_id.as_str()).bind::<sql_types::Bool,_>(progress.coverage.realm)
            .bind::<sql_types::Array<Text>,_>(&strands).bind::<sql_types::Bool,_>(all_members)
            .bind::<sql_types::Array<Text>,_>(&actors).bind::<sql_types::Array<Text>,_>(&events)
            .get_result::<Pending>(&mut *conn).await?;
        if pending.pending { return Ok(CurrentDetailOutcome::Unavailable); }
        let mut entries=Vec::new(); let mut bytes=0usize; let mut roster_rows=0usize;
        let mut complete=false;
        for _ in 0..100 {
            let is_live=progress.phase==CurrentDetailPhase::Live;
            let selection=Selection {realm_id:request.realm_id.as_str(),scope_keys:&[],candidate_scopes:true,
                realm:progress.coverage.realm,strand_ids:&strands,all_members,actor_keys:&actors,event_ids:&events,
                priority_selectors:if is_live {&[]} else {&priority}};
            let position=Position {revision:progress.scan_revision,selector_key:progress.scan_selector.clone()};
            let next=crate::current_results::read::next(conn,&selection,if is_live {cut} else {progress.cut_revision},&position,progress.phase==CurrentDetailPhase::Priority,!is_live).await?;
            let Some((position,entry))=next else {
                if progress.phase==CurrentDetailPhase::Priority {
                    progress.phase=CurrentDetailPhase::Ordinary; progress.scan_revision=0; progress.scan_selector.clear(); continue;
                }
                if was_baseline { complete=true; }
                progress.phase=CurrentDetailPhase::Live;
                progress.scan_revision=if was_baseline {progress.cut_revision} else {cut};
                // Every JCS selector starts with ASCII '{'; this marks the
                // fully consumed revision, unlike a partial selector position.
                progress.scan_selector="\u{7f}".to_owned();
                progress.retained_revision=progress.scan_revision;
                break;
            };
            let visible=scope_visible(conn,&actor,request,&entry.selector().scope_ref).await?;
            if visible {
                let roster_candidate=matches!(entry.selector().scope_ref,ScopeRef::Realm{..}) && matches!(entry.target(),CurrentTarget::Member{..}) && entry.selector().cell_id.as_str().starts_with("ak:cell:ak.component.member.state.v1:");
                // Leave room for the optional lightweight roster alongside the
                // worst legal baseline coverage and a 7 MiB current entry set.
                if roster_candidate && roster_rows>=32 { break; }
                #[derive(QueryableByName)]
                struct Sources { #[diesel(sql_type=sql_types::Bool)] valid:bool }
                let scope=String::from_utf8(arkret_canonical::canonical_json_bytes(&entry.selector().scope_ref).map_err(error)?).map_err(error)?;
                let source_ids=match entry.result() { CurrentOutcome::Heads{heads}=>heads.iter().map(|head|head.event_id.token_bytes().to_vec()).collect::<Vec<_>>(),_=>vec![] };
                let sources=sql_query("SELECT NOT EXISTS(SELECT 1 FROM current_data_sources s WHERE s.realm_id=$1 AND s.scope_key=$2 AND s.cell_id=$3 AND s.event_id=ANY($4) AND (NOT s.available OR NOT EXISTS(SELECT 1 FROM accepted_events e WHERE e.id=s.event_id))) AS valid")
                    .bind::<Text,_>(request.realm_id.as_str()).bind::<Text,_>(&scope).bind::<Text,_>(entry.selector().cell_id.as_str()).bind::<sql_types::Array<sql_types::Binary>,_>(&source_ids)
                    .get_result::<Sources>(&mut *conn).await?;
                if !sources.valid { return Ok(CurrentDetailOutcome::Unavailable); }
                let size=arkret_canonical::canonical_json_bytes(&entry).map_err(error)?.len()+1;
                if bytes.saturating_add(size)>byte_budget { break; }
                bytes+=size; if roster_candidate {roster_rows+=1;} entries.push(entry);
            }
            // Invisible candidates count toward work and advance the opaque
            // scan position. Empty intermediate pages are not completion.
            progress.scan_revision=position.revision; progress.scan_selector=position.selector_key;
            if is_live { progress.retained_revision=progress.scan_revision; }
        }
        let Some(final_authority)=read_authority(conn,&actor,request.realm_id.as_str()).await? else { return Ok(CurrentDetailOutcome::NotFound); };
        if !final_authority.ready || final_authority.revision!=progress.authority_revision { return Ok(CurrentDetailOutcome::Unavailable); }
        let baseline=was_baseline.then(||RealmDetailBaseline {snapshot_cursor:progress.snapshot_cursor.clone(),cut_revision:progress.cut_revision as u64,coverage:progress.coverage.clone(),complete});
        Ok(CurrentDetailOutcome::Page(CurrentDetailPage {progress,entries,baseline}))
    }).await.map_err(crate::PgTransactionError::into_persistence)
}
