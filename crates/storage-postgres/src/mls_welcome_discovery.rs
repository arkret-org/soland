//! Bounded recipient-window reads. Candidate/chain writers use the same clock lock.
use soland_storage::{MlsWelcomeDiscoveryPage, MlsWelcomeDiscoveryQuery};

use super::*;

#[derive(QueryableByName)]
struct ScopeRow {
    #[diesel(sql_type = BigInt)]
    revision: i64,
    #[diesel(sql_type = BigInt)]
    position: i64,
    #[diesel(sql_type = Bool)]
    available: bool,
}
#[derive(QueryableByName)]
struct WindowRow {
    #[diesel(sql_type = Jsonb)]
    scope: Value,
    #[diesel(sql_type = Text)]
    group_id: String,
    #[diesel(sql_type = Jsonb)]
    endpoint: Value,
    #[diesel(sql_type = Jsonb)]
    authority_context: Value,
    #[diesel(sql_type = diesel::sql_types::Integer)]
    page_limit: i32,
    #[diesel(sql_type = BigInt)]
    revision: i64,
    #[diesel(sql_type = BigInt)]
    upper_position: i64,
    #[diesel(sql_type = BigInt)]
    after_position: i64,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<chrono::Utc>,
}
#[derive(QueryableByName)]
struct RefRow {
    #[diesel(sql_type = Text)]
    event_ref: String,
    #[diesel(sql_type = BigInt)]
    position: i64,
}

#[derive(QueryableByName)]
struct MembershipRow {
    #[diesel(sql_type = BigInt)]
    revision: i64,
    #[diesel(sql_type = Nullable<Jsonb>)]
    current_value: Option<Value>,
    #[diesel(sql_type = Bool)]
    available: bool,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[derive(QueryableByName)]
    struct TestCount {
        #[diesel(sql_type = BigInt)]
        value: i64,
    }

    fn query() -> MlsWelcomeDiscoveryQuery {
        MlsWelcomeDiscoveryQuery {
            scope: json!({"kind":"realm","realm_id":"realm"}),
            group_id: "group".into(),
            endpoint: json!({"principal_id":"alice","station_id":"station","device_id":"device","agent_id":null,"verification_method":null}),
            authorization_ref: "authorize".into(),
            membership_cells: Vec::new(),
            authority_context: json!({"incarnation":1}),
            limit: 1,
            cursor: None,
            now: chrono::Utc::now(),
        }
    }
    async fn event(conn: &mut AsyncPgConnection, seed: u8, kind: &str, payload: Value) -> String {
        let mut id = vec![1];
        id.extend([seed; 32]);
        let reference = crate::ids::format_event_id(&id.try_into().unwrap());
        let envelope = json!({"event_id":reference,"scope_ref":query().scope,"payload":payload});
        sql_query("INSERT INTO canonical_events(id,digest_suite,digest,actor_id,actor_seq,realm_id,kind,schema_id,canonical_bytes,envelope) VALUES($1,1,$2,'author',$3,'realm',$4,'test',$5,$6)")
            .bind::<Binary,_>(crate::ids::parse_event_id(&reference).unwrap().to_vec()).bind::<Binary,_>(vec![seed;32]).bind::<BigInt,_>(i64::from(seed))
            .bind::<Text,_>(kind).bind::<Binary,_>(vec![seed]).bind::<Jsonb,_>(envelope).execute(conn).await.unwrap();
        reference
    }
    async fn welcome(conn: &mut AsyncPgConnection, seed: u8, commit: &str) -> String {
        let receipt = json!({"source_id":"source","destination_id":"station","claim_request_id":format!("request-{seed}"),"expires_at":"2099-01-01T00:00:00.000Z"});
        sql_query("INSERT INTO peer_keypackage_claims(source_id,claim_request_id,request_digest,key_package_use,keypackage_id,outcome,claim_expires_at_unix_ms,expires_at,state,updated_at) VALUES('source',$1,'digest','single_use',$2,$3,4070908800000,4070908800,'claimed',0)")
            .bind::<Text,_>(format!("request-{seed}")).bind::<Text,_>(format!("package-{seed}"))
            .bind::<Jsonb,_>(json!({"claim_receipt":receipt,"claims":[{"claim_id":format!("claim-{seed}") }]}))
            .execute(&mut *conn).await.unwrap();
        event(conn,seed,"ak.mls.welcome",json!({"mls_group_id":"group","recipient_principal_id":"alice","recipient_device_id":"device",
            "claim_ref":{"device_authorize_event_id":"authorize"},"claim_id":format!("claim-{seed}"),"commit_ref":commit,
            "expires_at":"2099-01-01T00:00:00.000Z","claim_receipt":{"source_id":"source","destination_id":"station","claim_request_id":format!("request-{seed}"),"expires_at":"2099-01-01T00:00:00.000Z"}})).await
    }
    async fn scope(conn: &mut AsyncPgConnection, head: &str) {
        sql_query("INSERT INTO mls_welcome_discovery_scopes(scope,group_id,realm_id,available,head) VALUES($1,'group','realm',TRUE,$2)")
            .bind::<Jsonb,_>(query().scope).bind::<Jsonb,_>(json!({"transition_ref":head})).execute(&mut *conn).await.unwrap();
        sql_query("INSERT INTO mls_welcome_discovery_chain(scope,group_id,epoch,event_ref) VALUES($1,'group',0,$2)")
            .bind::<Jsonb,_>(query().scope).bind::<Text,_>(head).execute(conn).await.unwrap();
    }
    #[tokio::test]
    async fn welcome_discovery_requires_live_exact_claim_and_preserves_other_claims() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let mut conn = pg_conn(&pool).await.unwrap();
        scope(&mut conn, "genesis").await;
        welcome(&mut conn, 61, "genesis").await;
        let retained = welcome(&mut conn, 62, "genesis").await;
        sql_query("UPDATE peer_keypackage_claims SET state='consumed' WHERE claim_request_id='request-61'")
            .execute(&mut *conn).await.unwrap();
        event(&mut conn,63,"ak.mls.welcome",json!({"mls_group_id":"group","recipient_principal_id":"alice","recipient_device_id":"device",
            "claim_ref":{"device_authorize_event_id":"authorize"},"claim_id":"absent","commit_ref":"genesis",
            "expires_at":"2099-01-01T00:00:00.000Z","claim_receipt":{"source_id":"source","destination_id":"station","claim_request_id":"missing","expires_at":"2099-01-01T00:00:00.000Z"}})).await;
        drop(conn);
        let page = discover(&pool, &query()).await.unwrap();
        assert_eq!(page.welcome_refs, vec![retained]);
        assert!(page.next_cursor.is_none());
    }

    #[tokio::test]
    async fn welcome_discovery_insertion_rolls_back_with_canonical_event() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let mut conn = pg_conn(&pool).await.unwrap();
        scope(&mut conn, "genesis").await;
        let result = conn
            .transaction::<(), diesel::result::Error, _>(async |conn| {
                welcome(conn, 64, "genesis").await;
                Err(diesel::result::Error::RollbackTransaction)
            })
            .await;
        assert!(result.is_err());
        let count = sql_query("SELECT count(*) AS value FROM mls_welcome_discovery_entries")
            .get_result::<TestCount>(&mut *conn)
            .await
            .unwrap()
            .value;
        assert_eq!(count, 0);
        let clock =
            sql_query("SELECT revision,position,available FROM mls_welcome_discovery_scopes")
                .get_result::<ScopeRow>(&mut *conn)
                .await
                .unwrap();
        assert_eq!(clock.position, 0);
    }

    #[tokio::test]
    async fn welcome_windows_freeze_upper_bound_and_reject_other_endpoint_or_revision() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let mut conn = pg_conn(&pool).await.unwrap();
        scope(&mut conn, "genesis").await;
        let first = welcome(&mut conn, 41, "genesis").await;
        let second = welcome(&mut conn, 42, "genesis").await;
        drop(conn);
        let mut q = query();
        let page = discover(&pool, &q).await.unwrap();
        assert_eq!(page.welcome_refs, vec![first]);
        q.cursor = page.next_cursor;
        let mut conn = pg_conn(&pool).await.unwrap();
        welcome(&mut conn, 43, "genesis").await;
        drop(conn);
        let mut foreign = q.clone();
        foreign.endpoint["device_id"] = json!("another-device");
        assert!(
            matches!(discover(&pool,&foreign).await,Err(PersistenceError::Conflict(code)) if code=="cursor_invalid")
        );
        let tail = discover(&pool, &q).await.unwrap();
        assert_eq!(tail.welcome_refs, vec![second]);
        assert!(tail.next_cursor.is_none());
        assert_eq!(
            discover(&pool, &q).await.unwrap().welcome_refs,
            tail.welcome_refs
        );
        let mut conn = pg_conn(&pool).await.unwrap();
        sql_query("UPDATE mls_welcome_discovery_scopes SET revision=revision+1")
            .execute(&mut *conn)
            .await
            .unwrap();
        drop(conn);
        assert!(
            matches!(discover(&pool,&q).await,Err(PersistenceError::Conflict(code)) if code=="cursor_invalid")
        );
    }
    #[tokio::test]
    async fn welcome_index_quarantine_invalidates_only_the_affected_chain_suffix() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let mut conn = pg_conn(&pool).await.unwrap();
        let genesis = event(&mut conn, 51, "ak.mls.genesis", json!({})).await;
        scope(&mut conn, &genesis).await;
        let commit = event(&mut conn, 52, "ak.mls.commit", json!({})).await;
        sql_query("INSERT INTO mls_welcome_discovery_chain(scope,group_id,epoch,event_ref) VALUES($1,'group',1,$2)")
            .bind::<Jsonb,_>(query().scope).bind::<Text,_>(&commit).execute(&mut *conn).await.unwrap();
        welcome(&mut conn, 53, &genesis).await;
        welcome(&mut conn, 54, &commit).await;
        let unrelated = event(&mut conn, 55, "ak.message", json!({})).await;
        sql_query("UPDATE canonical_events SET state='quarantined' WHERE id=$1")
            .bind::<Binary, _>(crate::ids::parse_event_id(&unrelated).unwrap().to_vec())
            .execute(&mut *conn)
            .await
            .unwrap();
        let unchanged =
            sql_query("SELECT revision,position,available FROM mls_welcome_discovery_scopes")
                .get_result::<ScopeRow>(&mut *conn)
                .await
                .unwrap();
        assert_eq!(unchanged.revision, 1);
        assert!(unchanged.available);
        sql_query("UPDATE canonical_events SET state='quarantined' WHERE id=$1")
            .bind::<Binary, _>(crate::ids::parse_event_id(&commit).unwrap().to_vec())
            .execute(&mut *conn)
            .await
            .unwrap();
        let affected =
            sql_query("SELECT revision,position,available FROM mls_welcome_discovery_scopes")
                .get_result::<ScopeRow>(&mut *conn)
                .await
                .unwrap();
        assert!(!affected.available);
        assert_eq!(affected.revision, 2);
        let rows=sql_query("SELECT event_ref,position FROM mls_welcome_discovery_entries WHERE eligible ORDER BY position").load::<RefRow>(&mut *conn).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].position, 1);
        let prefix = sql_query(
            "SELECT EXISTS(SELECT 1 FROM mls_welcome_discovery_chain WHERE epoch=0) AS present",
        )
        .get_result::<ExistsRow>(&mut *conn)
        .await
        .unwrap();
        assert!(prefix.present);
    }
}

pub(crate) async fn discover(
    pool: &PgPool,
    query: &MlsWelcomeDiscoveryQuery,
) -> PersistenceResult<MlsWelcomeDiscoveryPage> {
    if !(1..=100).contains(&query.limit) {
        return Err(PersistenceError::SchemaViolation(
            "Welcome page limit is outside 1..100".into(),
        ));
    }
    let mut conn = pg_conn(pool).await.map_err(PersistenceError::database)?;
    conn.transaction::<_,PgTransactionError,_>(async move |conn| {
        let clock=sql_query("SELECT revision,position,available FROM mls_welcome_discovery_scopes WHERE scope=$1 AND group_id=$2 FOR UPDATE")
            .bind::<Jsonb,_>(&query.scope).bind::<Text,_>(&query.group_id).get_result::<ScopeRow>(&mut *conn).await.optional()?
            .ok_or_else(||PersistenceError::Conflict("frontier_unavailable".into()))?;
        if !clock.available { return Err(PersistenceError::Conflict("frontier_unavailable".into()).into()); }
        if query.membership_cells.len()>2 { return Err(PersistenceError::SchemaViolation("Welcome membership selector exceeds two cells".into()).into()); }
        let realm=query.scope.get("realm_id").and_then(Value::as_str).ok_or_else(||PersistenceError::SchemaViolation("Welcome scope lacks Realm".into()))?;
        let mut pins=Vec::new();
        for cell in &query.membership_cells {
            let row=sql_query("SELECT revision,current_value,available FROM mls_welcome_discovery_membership WHERE realm_id=$1 AND cell_id=$2")
                .bind::<Text,_>(realm).bind::<Text,_>(cell).get_result::<MembershipRow>(&mut *conn).await.optional()?
                .ok_or_else(||PersistenceError::Conflict("not_found".into()))?;
            if !row.available {return Err(PersistenceError::Conflict("frontier_unavailable".into()).into());}
            if row.current_value.as_ref().and_then(Value::as_str)!=Some("join") {return Err(PersistenceError::Conflict("not_found".into()).into());}
            pins.push(serde_json::json!({"cell_id":cell,"revision":row.revision}));
        }
        let authority_context=serde_json::json!({"session":query.authority_context,"membership_pins":pins});
        // Retire at most one bounded maintenance page. Never silently skip an
        // expired index slot and continue an old window.
        let expired=sql_query("UPDATE mls_welcome_discovery_entries SET eligible=FALSE WHERE event_pk IN (SELECT event_pk FROM mls_welcome_discovery_entries WHERE scope=$1 AND group_id=$2 AND eligible AND expires_at<=$3 ORDER BY expires_at LIMIT 100)")
            .bind::<Jsonb,_>(&query.scope).bind::<Text,_>(&query.group_id).bind::<Timestamptz,_>(query.now).execute(&mut *conn).await?;
        let revision=if expired>0 {
            sql_query("UPDATE mls_welcome_discovery_scopes SET revision=revision+1 WHERE scope=$1 AND group_id=$2")
                .bind::<Jsonb,_>(&query.scope).bind::<Text,_>(&query.group_id).execute(&mut *conn).await?;
            clock.revision+1
        } else { clock.revision };
        let remaining=sql_query("SELECT EXISTS(SELECT 1 FROM mls_welcome_discovery_entries WHERE scope=$1 AND group_id=$2 AND eligible AND expires_at<=$3) AS present")
            .bind::<Jsonb,_>(&query.scope).bind::<Text,_>(&query.group_id).bind::<Timestamptz,_>(query.now).get_result::<ExistsRow>(&mut *conn).await?.present;
        // Return maintenance status after commit so this batch makes durable progress.
        if remaining { return Ok(Err(PersistenceError::Conflict("frontier_unavailable".into()))); }
        let (upper,after,expires)=if let Some(cursor)=&query.cursor {
            let id=Uuid::parse_str(cursor).map_err(|_|PersistenceError::Conflict("cursor_invalid".into()))?;
            let window=sql_query("SELECT scope,group_id,endpoint,authority_context,page_limit,revision,upper_position,after_position,expires_at FROM mls_welcome_discovery_windows WHERE id=$1")
                .bind::<diesel::sql_types::Uuid,_>(id).get_result::<WindowRow>(&mut *conn).await.optional()?;
            let Some(window)=window else {return Ok(Err(PersistenceError::Conflict("cursor_invalid".into())));};
            if window.scope!=query.scope || window.group_id!=query.group_id || window.endpoint!=query.endpoint
                || window.authority_context!=authority_context || window.page_limit!=query.limit as i32
                || window.revision!=revision || window.expires_at<=query.now {
                return Ok(Err(PersistenceError::Conflict("cursor_invalid".into())));
            }
            (window.upper_position,window.after_position,window.expires_at)
        } else {(clock.position,0,query.now+chrono::Duration::minutes(5))};
        let mut rows=sql_query("SELECT event_ref,position FROM mls_welcome_discovery_entries WHERE scope=$1 AND group_id=$2 AND endpoint=$3 AND eligible AND authorization_ref=$4 AND position>$5 AND position<=$6 ORDER BY position LIMIT $7")
            .bind::<Jsonb,_>(&query.scope).bind::<Text,_>(&query.group_id).bind::<Jsonb,_>(&query.endpoint)
            .bind::<Text,_>(&query.authorization_ref).bind::<BigInt,_>(after).bind::<BigInt,_>(upper).bind::<BigInt,_>(i64::from(query.limit)+1)
            .load::<RefRow>(&mut *conn).await?;
        let limited=rows.len()>query.limit as usize;
        rows.truncate(query.limit as usize);
        let next_cursor=if limited {
            let id=Uuid::new_v4();
            sql_query("INSERT INTO mls_welcome_discovery_windows(id,scope,group_id,endpoint,authority_context,page_limit,revision,upper_position,after_position,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
                .bind::<diesel::sql_types::Uuid,_>(id).bind::<Jsonb,_>(&query.scope).bind::<Text,_>(&query.group_id)
                .bind::<Jsonb,_>(&query.endpoint).bind::<Jsonb,_>(&authority_context).bind::<diesel::sql_types::Integer,_>(query.limit as i32)
                .bind::<BigInt,_>(revision).bind::<BigInt,_>(upper).bind::<BigInt,_>(rows.last().expect("limited page progresses").position)
                .bind::<Timestamptz,_>(expires).execute(&mut *conn).await?;
            Some(id.to_string())
        } else {None};
        sql_query("DELETE FROM mls_welcome_discovery_windows WHERE id IN (SELECT id FROM mls_welcome_discovery_windows WHERE expires_at<=$1 ORDER BY expires_at LIMIT 100)")
            .bind::<Timestamptz,_>(query.now).execute(&mut *conn).await?;
        Ok(Ok(MlsWelcomeDiscoveryPage {welcome_refs:rows.into_iter().map(|row|row.event_ref).collect(),next_cursor}))
    }).await.map_err(PgTransactionError::into_persistence)?
}
