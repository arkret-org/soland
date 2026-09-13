use super::*;

#[derive(QueryableByName)]
struct SigningBodyRow {
    #[diesel(sql_type = Text)]
    digest_suite: String,
    #[diesel(sql_type = Text)]
    body_digest: String,
    #[diesel(sql_type = Binary)]
    exact_body: Vec<u8>,
}

impl SigningBodyRow {
    fn decode(self) -> StoreResult<(arkret_wire::UnsignedSeal, arkret_canonical::DigestSuite)> {
        let suite = arkret_canonical::digest_suite(&self.digest_suite)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let body: arkret_wire::UnsignedSeal = serde_json::from_slice(&self.exact_body)
            .map_err(|error| StoreError::Backend(format!("invalid reserved Seal body: {error}")))?;
        let canonical = arkret_canonical::canonical_json_bytes(&body)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        if canonical != self.exact_body
            || arkret_canonical::digest(suite, &canonical) != self.body_digest
        {
            return Err(StoreError::Backend(
                "reserved Seal body integrity mismatch".to_owned(),
            ));
        }
        Ok((body, suite))
    }
}

async fn load_body(
    conn: &mut AsyncPgConnection,
    realm: &str,
    sequence: i64,
) -> StoreResult<Option<SigningBodyRow>> {
    sql_query("SELECT digest_suite, body_digest, exact_body FROM state_seal_signing_positions WHERE realm_id=$1 AND notary_seq=$2")
        .bind::<Text,_>(realm).bind::<BigInt,_>(sequence)
        .get_result(conn).await.optional().map_err(diesel_to_store)
}

pub(super) async fn signing_body(
    store: &PgSealStore,
    realm: &RealmId,
    sequence: u64,
) -> StoreResult<Option<arkret_wire::UnsignedSeal>> {
    let sequence =
        i64::try_from(sequence).map_err(|error| StoreError::Conflict(error.to_string()))?;
    let mut conn = pg_conn(&store.pool).await?;
    let body = load_body(&mut conn, realm.as_str(), sequence)
        .await?
        .map(SigningBodyRow::decode)
        .transpose()?;
    if let Some((body, _)) = &body {
        if body.realm_id != *realm || body.notary_seq != sequence as u64 {
            return Err(StoreError::Backend(
                "reserved Seal position differs from its body".into(),
            ));
        }
    }
    Ok(body.map(|(body, _)| body))
}

pub(super) async fn reserve_signing_body(
    store: &PgSealStore,
    body: &arkret_wire::UnsignedSeal,
    suite: arkret_canonical::DigestSuite,
) -> StoreResult<arkret_wire::UnsignedSeal> {
    let sequence =
        i64::try_from(body.notary_seq).map_err(|error| StoreError::Conflict(error.to_string()))?;
    let canonical = arkret_canonical::canonical_json_bytes(body)
        .map_err(|error| StoreError::Conflict(error.to_string()))?;
    let digest = arkret_canonical::digest(suite, &canonical);
    let mut conn = pg_conn(&store.pool).await?;
    conn.transaction::<_, EventSealCommitError, _>(async |conn| {
        lock_seal_realm(conn, body.realm_id.as_str()).await?;
        if realm_has_seal_collision(conn, body.realm_id.as_str()).await? {
            return Err(StoreError::Conflict("cannot reserve a quarantined Realm signing position".into()).into());
        }
        if let Some(row) = load_body(conn, body.realm_id.as_str(), sequence).await? {
            let (reserved, reserved_suite) = row.decode()?;
            if reserved.realm_id != body.realm_id || reserved.notary_seq != body.notary_seq || reserved_suite != suite {
                return Err(StoreError::Conflict("reserved Seal position or digest suite mismatch".into()).into());
            }
            return Ok(reserved);
        }
        let heads = sql_query("SELECT seal_json AS value FROM state_seals parent WHERE realm_id=$1 AND NOT EXISTS (SELECT 1 FROM state_seal_quarantine q WHERE q.seal_id=parent.id) AND NOT EXISTS (SELECT 1 FROM state_seals child WHERE child.realm_id=parent.realm_id AND child.predecessor_ref=parent.id AND NOT EXISTS (SELECT 1 FROM state_seal_quarantine q WHERE q.seal_id=child.id)) ORDER BY parent.id")
            .bind::<Text,_>(body.realm_id.as_str()).load::<JsonRow>(conn).await?;
        let head = match heads.as_slice() {
            [] => None,
            [row] => Some(serde_json::from_value::<Seal>(row.value.clone()).map_err(serde_to_store)?),
            _ => return Err(StoreError::Conflict("multiple confirmed Realm heads".into()).into()),
        };
        let expected_sequence = match &head {
            None => 0,
            Some(head) => head.notary_seq.checked_add(1).ok_or_else(|| StoreError::Conflict("Seal sequence overflow".into()))?,
        };
        if head.as_ref().map(|head| &head.id) != body.predecessor_ref.as_ref() || expected_sequence != body.notary_seq {
            return Err(StoreError::Conflict("Seal signing position has a stale predecessor or sequence".into()).into());
        }
        sql_query("INSERT INTO state_seal_signing_positions (realm_id,configuration_ref,notary_seq,predecessor_ref,digest_suite,body_digest,exact_body) VALUES ($1,$2,$3,$4,$5,$6,$7)")
            .bind::<Text,_>(body.realm_id.as_str()).bind::<Text,_>(body.configuration_ref.as_str())
            .bind::<BigInt,_>(sequence).bind::<Nullable<Text>,_>(body.predecessor_ref.as_ref().map(SealId::as_str))
            .bind::<Text,_>(suite.as_str()).bind::<Text,_>(&digest).bind::<Binary,_>(&canonical).execute(conn).await?;
        Ok(body.clone())
    }).await.map_err(EventSealCommitError::into_store)
}

pub(super) async fn validate_reserved_body(
    conn: &mut AsyncPgConnection,
    insert: &StateSealInsert<'_>,
) -> StoreResult<()> {
    let body: arkret_wire::UnsignedSeal = serde_json::from_slice(insert.seal_id_preimage_bytes)
        .map_err(|error| StoreError::Conflict(error.to_string()))?;
    let sequence =
        i64::try_from(body.notary_seq).map_err(|error| StoreError::Conflict(error.to_string()))?;
    if let Some(row) = load_body(conn, insert.realm_id, sequence).await? {
        if row.digest_suite != insert.digest_suite.as_str()
            || row.exact_body != insert.seal_id_preimage_bytes
        {
            return Err(StoreError::Conflict(
                "accepted Seal differs from the immutable signing position".into(),
            ));
        }
        row.decode()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate() -> arkret_wire::UnsignedSeal {
        let event = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [33; 32]);
        let digest = Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap();
        arkret_wire::UnsignedSeal {
            realm_id: RealmId::from_event_id(&event),
            predecessor_ref: None,
            delta: vec![],
            data_delta: vec![],
            data_event_set_root: arkret_wire::empty_data_event_set_root(
                arkret_canonical::DigestSuite::Sha256,
            )
            .unwrap(),
            control_event_set_root: digest.clone(),
            state_root: digest,
            notary_seq: 0,
            availability_receipt_digests: vec![],
            covered_event_digests: vec![],
            previous_state_root: None,
            previous_digest_algorithm: None,
            sealed_at: chrono::DateTime::parse_from_rfc3339("2026-09-12T00:00:00.000Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            hlc: arkret_wire::Hlc::new("0189c4d2af00-0000-aabbccdd").unwrap(),
            configuration_ref: event,
            command_results: vec![],
            authorization_closures: vec![],
            data_closure_announcements: vec![],
            data_closures: vec![],
            existence_anchors: vec![],
        }
    }

    #[tokio::test]
    async fn postgres_signing_position_survives_restart_and_rejects_alternate_commit() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let first = PgSealStore { pool: pool.clone() };
        let second = PgSealStore { pool: pool.clone() };
        let body = candidate();
        let mut alternate = body.clone();
        alternate.sealed_at += chrono::Duration::milliseconds(1);
        let suite = arkret_canonical::DigestSuite::Sha256;
        let (left, right) = tokio::join!(
            first.reserve_signing_body(&body, suite),
            second.reserve_signing_body(&alternate, suite),
        );
        let fixed = left.unwrap();
        assert_eq!(
            right.unwrap(),
            fixed,
            "only one exact body can win the position"
        );
        let restarted = PgSealStore { pool: pool.clone() };
        assert_eq!(
            restarted.signing_body(&body.realm_id, 0).await.unwrap(),
            Some(fixed.clone())
        );
        assert!(
            restarted
                .reserve_signing_body(&body, arkret_canonical::DigestSuite::Blake3)
                .await
                .is_err()
        );
        let losing_body = if fixed == body {
            alternate
        } else {
            body.clone()
        };
        let unsigned_bytes = arkret_canonical::canonical_json_bytes(&losing_body).unwrap();
        let transcript = arkret_canonical::canonical_json_bytes(&serde_json::json!({
            "context": "ak.seal.commit.v1",
            "seal_digest": arkret_canonical::digest(suite, &unsigned_bytes),
        }))
        .unwrap();
        let signature = arkret_wire::SealSignature {
            verification_method: arkret_wire::DidUrl::new("did:web:authority.example#notary")
                .unwrap(),
            payload_digest: Hash::new(arkret_canonical::digest(suite, &transcript)).unwrap(),
            jws: "eyJhbGciOiJFZDI1NTE5In0..AQ".to_owned(),
        };
        let losing =
            Seal::from_canonical_body_and_signature(&unsigned_bytes, signature, suite).unwrap();
        assert!(restarted.put_if_head(&losing, None, suite).await.is_err());
        assert!(
            restarted
                .confirmed_head(&body.realm_id)
                .await
                .unwrap()
                .is_none()
        );
        let mut stale = candidate();
        stale.notary_seq = 1;
        assert!(restarted.reserve_signing_body(&stale, suite).await.is_err());
    }
}
