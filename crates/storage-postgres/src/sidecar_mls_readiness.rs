//! Endpoint readiness consumes formal delivery/claim evidence at the read cut.
use arkret_wire::{ActorId, EventId, MlsWelcomeDelivery, MlsWelcomeRecipientEndpoint, ScopeRef};
use diesel::sql_types::{Binary, Jsonb, Text};
use diesel::{OptionalExtension, QueryableByName};
use diesel_async::RunQueryDsl;

#[derive(QueryableByName)]
struct Evidence {
    #[diesel(sql_type = Jsonb)]
    delivery: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    receipt: serde_json::Value,
    #[diesel(sql_type = Text)]
    claim_request_id: String,
    #[diesel(sql_type = Text)]
    request_digest: String,
    #[diesel(sql_type = Text)]
    keypackage_ref: String,
}

#[derive(QueryableByName)]
struct PublicState {
    #[diesel(sql_type = Binary)]
    public_state: Vec<u8>,
}

#[derive(QueryableByName)]
struct AcceptedGroup {
    #[diesel(sql_type = Binary)]
    public_state: Vec<u8>,
    #[diesel(sql_type = Jsonb)]
    envelope: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    genesis: serde_json::Value,
}

pub(crate) async fn controller_device_ready_in_connection(
    conn: &mut crate::AsyncPgConnection,
    cut: &crate::sidecar_authority_cut::SidecarParticipantAuthorityCut,
    current: &arkret_wire::MlsGroupCurrent,
    device: &arkret_wire::DeviceId,
) -> soland_storage::PersistenceResult<bool> {
    use soland_storage::PersistenceError;
    let Some(status) =
        crate::pcr_device_status_reader::confirmed_pcr_device_status_cut_in_connection(
            conn,
            &cut.controller_account_id,
            device,
            chrono::Utc::now(),
        )
        .await
        .map_err(crate::PgTransactionError::into_persistence)?
    else {
        return Ok(false);
    };
    if status.lifecycle != crate::pcr_device_status_fold::PcrDeviceLifecycle::Active {
        return Ok(false);
    }
    let Some(authorization) = status.authority.authorization else {
        return Ok(false);
    };
    let key = authorization
        .payload
        .device_public_key_did
        .as_str()
        .strip_prefix("did:key:")
        .ok_or_else(|| {
            PersistenceError::SchemaViolation("Sidecar controller key is not did:key".into())
        })?;
    let key = arkret_canonical::multibase::decode_ed25519_multibase(key)
        .map_err(PersistenceError::database)?;
    let key = arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(&key))
        .map_err(PersistenceError::database)?;
    let actor = ActorId::account(cut.controller_account_id.clone());
    let scope = ScopeRef::Sidecar {
        realm_id: cut.realm_id.clone(),
        sidecar_id: cut.sidecar_id.clone(),
    };
    if current.effective_scope != scope {
        return Ok(false);
    }
    let scope_key = crate::mls_group_current_results::scope_key(&scope)?;
    let group = diesel::sql_query("SELECT g.public_state,e.envelope,genesis.envelope AS genesis FROM mls_group_current_results g \
        JOIN realm_commits c ON c.commit_id=g.current_commit_id AND c.realm_id=g.realm_id AND c.stream_position=g.current_stream_position \
        JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' \
        JOIN canonical_events genesis ON genesis.envelope->>'event_id'=g.value->>'genesis_event_ref' AND genesis.state='committed' \
        WHERE g.scope_key=$1 AND (g.value->>'epoch')::bigint=$2")
        .bind::<Text,_>(&scope_key).bind::<diesel::sql_types::BigInt,_>(i64::try_from(current.epoch).map_err(PersistenceError::database)?)
        .get_result::<AcceptedGroup>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let Some(group) = group else {
        return Ok(false);
    };
    let event: arkret_wire::Event =
        serde_json::from_value(group.envelope).map_err(PersistenceError::database)?;
    let binding = match event.kind {
        arkret_wire::EventKind::MlsGenesis => serde_json::from_value::<
            arkret_models_collaboration::events_payloads::MlsGenesisPayload,
        >(
            serde_json::to_value(event.payload).map_err(PersistenceError::database)?,
        )
        .map_err(PersistenceError::database)?
        .governance_binding,
        arkret_wire::EventKind::MlsCommit => serde_json::from_value::<
            arkret_models_collaboration::events_payloads::MlsCommitPayload,
        >(
            serde_json::to_value(event.payload).map_err(PersistenceError::database)?,
        )
        .map_err(PersistenceError::database)?
        .governance_binding()
        .clone(),
        _ => return Ok(false),
    };
    if binding.effective_scope() != &scope
        || binding.sidecar_binding().is_none_or(|binding| {
            binding.participant_authority_digest != cut.participant_authority_digest
                || binding.authority_stream_head != cut.authority_stream_head
        })
    {
        return Ok(false);
    }
    let leaves = arkret_mls::MlsPublicGroupTracker::restore(
        &group.public_state,
        scope
            .canonical_mls_group_id()
            .map_err(PersistenceError::database)?
            .as_str(),
        current.epoch,
    )
    .and_then(|tracker| tracker.leaves())
    .map_err(PersistenceError::database)?;
    if !leaves
        .iter()
        .any(|leaf| leaf.actor_id == actor && leaf.signature_key == key)
    {
        return Ok(false);
    }
    let genesis: arkret_wire::Event =
        serde_json::from_value(group.genesis).map_err(PersistenceError::database)?;
    if genesis.scope_ref == scope
        && genesis.actor_id == actor
        && genesis
            .human_device_producer()
            .map_err(PersistenceError::database)?
            .is_some_and(|producer| producer.device_id == *device)
    {
        return Ok(true);
    }
    consumed_endpoint_in_connection(
        conn,
        &scope,
        &actor,
        &MlsWelcomeRecipientEndpoint::Device {
            device_id: device.clone(),
        },
        &authorization.event_id,
        &key,
        current.epoch,
    )
    .await
}

pub(crate) async fn consumed_endpoint_in_connection(
    conn: &mut crate::AsyncPgConnection,
    scope: &ScopeRef,
    actor: &ActorId,
    endpoint: &MlsWelcomeRecipientEndpoint,
    authorization_ref: &EventId,
    signature_key: &arkret_wire::Base64UrlString,
    current_epoch: u64,
) -> soland_storage::PersistenceResult<bool> {
    use arkret_models_crypto::http_bodies::{KeyPackageConsumeReceipt, RecipientMlsDurableSigner};
    use soland_storage::PersistenceError;
    let invalid = |message: &str| PersistenceError::SchemaViolation(message.to_owned());
    let scope_key = crate::mls_group_current_results::scope_key(scope)?;
    let group = scope
        .canonical_mls_group_id()
        .map_err(PersistenceError::database)?;
    let public = diesel::sql_query("SELECT public_state FROM mls_group_current_results WHERE scope_key=$1 AND (value->>'epoch')::bigint=$2")
        .bind::<Text,_>(&scope_key).bind::<diesel::sql_types::BigInt,_>(i64::try_from(current_epoch).map_err(PersistenceError::database)?)
        .get_result::<PublicState>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let Some(public) = public else {
        return Ok(false);
    };
    let leaves = arkret_mls::MlsPublicGroupTracker::restore(
        &public.public_state,
        group.as_str(),
        current_epoch,
    )
    .and_then(|tracker| tracker.leaves())
    .map_err(PersistenceError::database)?;
    // An old consume receipt does not make a removed or replaced leaf ready.
    // The caller supplies the key from its accepted current authorization.
    if !leaves
        .iter()
        .any(|leaf| leaf.actor_id == *actor && leaf.signature_key == *signature_key)
    {
        return Ok(false);
    }
    let token = crate::ids::parse_event_id(authorization_ref.as_str())
        .ok_or_else(|| invalid("Sidecar endpoint authorization ref is invalid"))?;
    let account = actor
        .as_account_id()
        .ok_or_else(|| invalid("Sidecar endpoint actor is not an Account"))?;
    let (device, method) = match endpoint {
        MlsWelcomeRecipientEndpoint::Device { device_id } => (device_id.as_str(), ""),
        MlsWelcomeRecipientEndpoint::AgentRuntime {
            verification_method,
        } => ("", verification_method.as_str()),
    };
    let evidence = diesel::sql_query("SELECT convert_from(w.delivery_canonical_json,'UTF8')::jsonb AS delivery, \
        p.consume_receipt AS receipt,p.claim_request_id,p.request_digest,k.keypackage_ref \
        FROM mls_key_packages k JOIN peer_keypackage_claims p ON p.keypackage_id=k.id \
        JOIN keypackage_claim_welcome_bindings b ON b.source_id=p.source_id AND b.claim_request_id=p.claim_request_id \
        JOIN mls_welcome_provenance w ON w.claim_id=b.claim_id AND w.welcome_id=b.welcome_id AND w.commit_event_ref=b.commit_event_ref \
        JOIN canonical_events e ON e.envelope->>'event_id'=w.commit_event_ref AND e.state='committed' \
        JOIN realm_commits c ON c.event_pk=e.pk \
        JOIN mls_group_current_results g ON g.scope_key=w.scope_key \
        WHERE k.actor_id=$1 AND w.scope_key=$2 AND w.recipient_station_id=$3 \
        AND p.state='consumed' AND p.consume_receipt IS NOT NULL \
        AND b.welcome_digest=w.delivery_digest AND c.stream_ref=jsonb_build_object('kind','sidecar','realm_id',w.realm_id,'sidecar_id',$4) \
        AND c.stream_position<=g.current_stream_position \
        AND (($5<>'' AND k.device_id=$5 AND k.device_authorize_event_id=$7) \
          OR ($6<>'' AND k.endpoint_verification_method=$6 AND k.agent_key_authorize_event_id=$7)) \
        AND ((NOT k.last_resort AND p.key_package_use='single_use' AND k.consumed_at IS NOT NULL AND k.claimed_by_mls_group_id=$8) \
          OR (k.last_resort AND p.key_package_use='last_resort'))")
        .bind::<Text,_>(actor.to_string()).bind::<Text,_>(&scope_key).bind::<Text,_>(account.station_id.as_str())
        .bind::<Text,_>(scope.sidecar_id().ok_or_else(|| invalid("Sidecar readiness requires native scope"))?.as_str())
        .bind::<Text,_>(device).bind::<Text,_>(method).bind::<Binary,_>(token.to_vec()).bind::<Text,_>(group.as_str())
        .load::<Evidence>(&mut *conn).await.map_err(PersistenceError::database)?;
    for evidence in evidence {
        let delivery: MlsWelcomeDelivery =
            serde_json::from_value(evidence.delivery).map_err(PersistenceError::database)?;
        let receipt: KeyPackageConsumeReceipt =
            serde_json::from_value(evidence.receipt).map_err(PersistenceError::database)?;
        delivery
            .validate_shape()
            .map_err(PersistenceError::database)?;
        receipt.validate_shape().map_err(invalid)?;
        let durable = &receipt.recipient_durable_receipt;
        let signer_matches = match (&durable.recipient, endpoint) {
            (
                RecipientMlsDurableSigner::Device {
                    recipient_account_id,
                    recipient_device_id,
                    ..
                },
                MlsWelcomeRecipientEndpoint::Device { device_id },
            ) => recipient_account_id == account && recipient_device_id == device_id,
            (
                RecipientMlsDurableSigner::Agent {
                    recipient_agent_id,
                    recipient_agent_verification_method,
                    agent_key_authorize_event_id,
                },
                MlsWelcomeRecipientEndpoint::AgentRuntime {
                    verification_method,
                },
            ) => {
                recipient_agent_id == &account.principal_id
                    && recipient_agent_verification_method == verification_method
                    && agent_key_authorize_event_id == authorization_ref
            }
            _ => false,
        };
        if delivery.effective_scope == *scope
            && delivery.recipient_actor_id == *actor
            && delivery.recipient_endpoint == *endpoint
            && receipt.claim_id == delivery.keypackage_claim_ref
            && durable.welcome_ref == delivery.welcome_id
            && durable.welcome_digest
                == delivery
                    .durable_receipt_digest()
                    .map_err(PersistenceError::database)?
            && durable.claim_request_id.as_str() == evidence.claim_request_id
            && receipt.request_digest.as_str() == evidence.request_digest
            && durable.key_package_ref.as_str() == evidence.keypackage_ref
            && durable.recipient_id == account.station_id
            && durable.realm_id == *scope.realm_id()
            && durable.mls_group_id == group
            && durable.mls_epoch <= current_epoch
            && signer_matches
        {
            return Ok(true);
        }
    }
    Ok(false)
}
