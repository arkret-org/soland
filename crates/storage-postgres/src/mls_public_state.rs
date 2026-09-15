mod authority;
mod commit;
pub(crate) use authority::read_authorizations;
use diesel::sql_types::{BigInt, Binary, Jsonb, Nullable, Text};
use diesel::{OptionalExtension, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use soland_storage::{EventCommitRequest, PersistenceError, PersistenceResult};

#[derive(diesel::QueryableByName)]
struct StoredGenesis {
    #[diesel(sql_type = Binary)]
    input_bytes: Vec<u8>,
}

#[derive(diesel::QueryableByName)]
struct GenesisReadRow {
    #[diesel(sql_type = Jsonb)]
    envelope: serde_json::Value,
    #[diesel(sql_type = Binary)]
    public_state: Vec<u8>,
    #[diesel(sql_type = Text)]
    producer_signing_key: String,
    #[diesel(sql_type = Nullable<Jsonb>)]
    producer_device_authorization: Option<serde_json::Value>,
}

pub(crate) async fn read_genesis(
    conn: &mut AsyncPgConnection,
    event_id: &arkret_wire::EventId,
) -> PersistenceResult<Option<soland_storage::MlsPublicGenesisRecord>> {
    let token =
        soland_storage::ids::event_token_part_or_schema_violation(event_id.as_str(), "event")?;
    let row = sql_query("SELECT e.envelope,g.public_state,g.producer_signing_key,g.producer_device_authorization FROM mls_public_genesis_states g JOIN canonical_events e ON e.pk=g.event_pk WHERE e.id=$1 AND e.state='accepted' AND g.source_available AND g.source_canonical_bytes=e.canonical_bytes")
        .bind::<Binary,_>(token.to_vec()).get_result::<GenesisReadRow>(conn).await.optional()
        .map_err(PersistenceError::database)?;
    row.map(|row| {
        Ok(soland_storage::MlsPublicGenesisRecord {
            source_event: serde_json::from_value(row.envelope)
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?,
            public_state: row.public_state,
            producer_signing_key: arkret_wire::DidKey::new(row.producer_signing_key)
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?,
            producer_device_authorization: row
                .producer_device_authorization
                .map(serde_json::from_value)
                .transpose()
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?,
        })
    })
    .transpose()
}

/// Validate and retain public bytes in the same transaction as their Event.
/// This does not assign a winning epoch or claim membership-origin readiness.
pub(crate) async fn commit_genesis(
    conn: &mut AsyncPgConnection,
    event_pk: i64,
    request: &EventCommitRequest,
) -> PersistenceResult<()> {
    let event: arkret_wire::Event = serde_json::from_value(request.event.envelope.clone())
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let fail =
        |message: &str| PersistenceError::Conflict(format!("failed_precondition: {message}"));
    if matches!(event.scope_ref, arkret_wire::ScopeRef::Sidecar { .. }) {
        return if request.mls_public_genesis.is_none() && request.mls_public_producer.is_none() {
            Ok(())
        } else {
            Err(fail(
                "Realm/Circle public tracker input cannot enter a Sidecar group",
            ))
        };
    }

    if matches!(
        event.kind.as_str(),
        "ak.mls.genesis" | "ak.mls.proposal" | "ak.mls.commit"
    ) {
        sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind::<Text, _>(event.realm_id.as_str())
            .execute(conn)
            .await
            .map_err(PersistenceError::database)?;
    }

    if matches!(event.kind.as_str(), "ak.mls.proposal" | "ak.mls.commit") {
        if request.mls_public_genesis.is_some() {
            return Err(fail("MLS handshake must not carry Genesis public material"));
        }
        return commit::commit_handshake(
            conn,
            event_pk,
            &event,
            request.mls_public_producer.as_ref(),
        )
        .await;
    }
    if request.mls_public_producer.is_some() {
        return Err(fail(
            "MLS producer input belongs only to Proposal or Commit",
        ));
    }
    if event.kind.as_str() != "ak.mls.genesis" {
        return if request.mls_public_genesis.is_none() {
            Ok(())
        } else {
            Err(fail("public Genesis input requires an MLS Genesis Event"))
        };
    }
    let input = request
        .mls_public_genesis
        .as_ref()
        .ok_or_else(|| fail("MLS Genesis requires exact validated public material"))?;
    let payload: arkret_models_collaboration::events_payloads::MlsGenesisPayload =
        serde_json::from_value(
            serde_json::to_value(&event.payload)
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?,
        )
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if payload.effective_scope() != &event.scope_ref {
        return Err(fail("MLS Genesis effective scope does not match its Event"));
    }
    if payload
        .effective_scope()
        .canonical_mls_group_id()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?
        != payload.mls_group_id()
    {
        return Err(fail(
            "MLS Genesis group id is not derived from its effective scope",
        ));
    }
    let limit = arkret_models_collaboration::mls_group_state_material::MLS_GROUP_STATE_MATERIAL_MAX_RESPONSE_BYTES as usize;
    if input
        .group_info_bytes
        .len()
        .checked_add(input.ratchet_tree_bytes.len())
        .is_none_or(|length| length > limit)
    {
        return Err(fail(
            "MLS Genesis public material exceeds the registered material bound",
        ));
    }
    for (reference, bytes) in [
        (&payload.group_info_ref, &input.group_info_bytes),
        (&payload.ratchet_tree_ref, &input.ratchet_tree_bytes),
    ] {
        let digest =
            arkret_models_collaboration::mls_group_state_material::material_digest_from_ref(
                reference,
            )
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        if digest
            .digest_suite()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?
            != request.event.digest_suite
        {
            return Err(fail(
                "MLS public material digest suite differs from its Realm",
            ));
        }
        arkret_canonical::canonical::verify_digest(bytes, digest.as_str()).map_err(|_| {
            fail("MLS public material bytes do not match the exact Genesis reference")
        })?;
    }
    let tracker = arkret_mls::MlsPublicGroupTracker::from_external(
        &input.group_info_bytes,
        &input.ratchet_tree_bytes,
        payload.mls_group_id(),
        0,
        Some(&payload.governance_binding),
    )
    .map_err(|error| match error {
        arkret_mls::MlsError::UnsupportedFeature(message) => {
            PersistenceError::Conflict(format!("unsupported_feature: {message}"))
        }
        error => PersistenceError::Conflict(format!("failed_precondition: {error}")),
    })?;
    if tracker.ciphersuite_name() != payload.cipher_suite.as_str() {
        return Err(fail(
            "MLS Genesis cipher suite does not match its public GroupContext",
        ));
    }
    let leaves = tracker
        .leaves()
        .map_err(|error| PersistenceError::Conflict(format!("failed_precondition: {error}")))?;
    let [creator] = leaves.as_slice() else {
        return Err(fail(
            "MLS Genesis public tree must contain exactly its creator leaf",
        ));
    };
    let key = arkret_canonical::decode_ed25519_multibase(
        input
            .producer_signing_key
            .as_str()
            .strip_prefix("did:key:")
            .ok_or_else(|| fail("MLS Genesis producer key is not did:key"))?,
    )
    .map_err(|_| fail("MLS Genesis producer key is not Ed25519"))?;
    if creator.leaf_index != 0
        || creator.signature_key.as_str() != arkret_canonical::base64url_encode(&key)
    {
        return Err(fail(
            "MLS Genesis creator leaf does not use the verified producer key",
        ));
    }
    match &creator.endpoint_credential {
        arkret_mls::MlsPublicLeafEndpointCredential::HumanDevice { device_id }
            if input.producer_device_id.as_ref() == Some(device_id) => {}
        arkret_mls::MlsPublicLeafEndpointCredential::Actor { actor_id }
            if actor_id.as_str()
                == event
                    .executed_by
                    .as_ref()
                    .unwrap_or(&event.actor_id)
                    .signing_principal_id()
                    .as_str() => {}
        _ => {
            return Err(fail(
                "MLS Genesis creator credential differs from its verified producer",
            ));
        }
    }
    let input_bytes = arkret_canonical::canonical_json_bytes(&serde_json::json!({
        "group_info": arkret_canonical::base64url_encode(&input.group_info_bytes),
        "ratchet_tree": arkret_canonical::base64url_encode(&input.ratchet_tree_bytes),
        "producer_signing_key": input.producer_signing_key,
        "producer_device_id": input.producer_device_id,
    }))
    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let public_state = tracker
        .export_state()
        .map_err(|error| PersistenceError::Conflict(format!("failed_precondition: {error}")))?;
    let authorization = request
        .device_revocation_gate
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let leaf_authorizations = match authority::retained(conn, &event.event_id, false).await? {
        Some(original) => original,
        None => {
            let leaf = arkret_wire::mls_transition::MlsSecurityFrontierLeaf {
                leaf_index: creator.leaf_index,
                actor_id: event
                    .executed_by
                    .as_ref()
                    .unwrap_or(&event.actor_id)
                    .clone(),
                credential_ref: creator.credential_ref.clone(),
            };
            let origin = authority::genesis_origin(request, &event, &leaf, &creator.signature_key)?;
            origin.map(|origin| vec![origin])
        }
    };
    sql_query("INSERT INTO mls_public_genesis_states (event_pk,input_bytes,public_state,producer_signing_key,producer_device_authorization,source_canonical_bytes,source_available) VALUES ($1,$2,$3,$4,$5,$6,TRUE) ON CONFLICT (event_pk) DO UPDATE SET source_available=TRUE,input_bytes=EXCLUDED.input_bytes,public_state=EXCLUDED.public_state,producer_signing_key=EXCLUDED.producer_signing_key,producer_device_authorization=EXCLUDED.producer_device_authorization,source_canonical_bytes=EXCLUDED.source_canonical_bytes WHERE mls_public_genesis_states.source_canonical_bytes<>EXCLUDED.source_canonical_bytes OR mls_public_genesis_states.input_bytes=EXCLUDED.input_bytes")
        .bind::<BigInt,_>(event_pk).bind::<Binary,_>(&input_bytes).bind::<Binary,_>(public_state)
        .bind::<Text,_>(input.producer_signing_key.as_str()).bind::<Nullable<Jsonb>,_>(authorization)
        .bind::<Binary,_>(&request.event.canonical_bytes)
        .execute(conn).await.map_err(PersistenceError::database)?;
    let stored = sql_query("SELECT input_bytes FROM mls_public_genesis_states WHERE event_pk=$1 AND source_canonical_bytes=$2")
        .bind::<BigInt, _>(event_pk)
        .bind::<Binary,_>(&request.event.canonical_bytes)
        .get_result::<StoredGenesis>(conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
    if stored.is_none_or(|stored| stored.input_bytes != input_bytes) {
        return Err(PersistenceError::Conflict(
            "MLS Genesis public input changed on exact retry".to_owned(),
        ));
    }
    sql_query("UPDATE mls_public_genesis_states SET leaf_authorizations=$2 WHERE event_pk=$1")
        .bind::<BigInt, _>(event_pk)
        .bind::<Nullable<Jsonb>, _>(
            leaf_authorizations
                .map(serde_json::to_value)
                .transpose()
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
        )
        .execute(conn)
        .await
        .map_err(PersistenceError::database)?;
    Ok(())
}

#[cfg(test)]
mod tests;
