//! Historical authority is frozen with public candidates, never filled on read.
use arkret_models_crypto::MlsAcceptedLeafAuthorization;
use arkret_wire::EventId;
use arkret_wire::mls_transition::MlsSecurityFrontierLeaf;
use diesel::sql_types::{Binary, Jsonb, Nullable};
use diesel::{OptionalExtension, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use soland_storage::{PersistenceError, PersistenceResult};

#[derive(diesel::QueryableByName)]
struct AuthorityRow {
    #[diesel(sql_type = Nullable<Jsonb>)]
    leaf_authorizations: Option<serde_json::Value>,
}

pub(crate) async fn read_authorizations(
    conn: &mut AsyncPgConnection,
    event_id: &EventId,
) -> PersistenceResult<Option<Vec<MlsAcceptedLeafAuthorization>>> {
    Ok(retained(conn, event_id, true).await?.flatten())
}

pub(super) async fn retained(
    conn: &mut AsyncPgConnection,
    event_id: &EventId,
    require_available: bool,
) -> PersistenceResult<Option<Option<Vec<MlsAcceptedLeafAuthorization>>>> {
    let row = sql_query("SELECT g.leaf_authorizations FROM mls_public_genesis_states g JOIN canonical_events e ON e.pk=g.event_pk WHERE e.id=$1 AND e.state='accepted' AND (g.source_available OR NOT $2) AND g.source_canonical_bytes=e.canonical_bytes UNION ALL SELECT c.leaf_authorizations FROM mls_public_commit_states c JOIN canonical_events e ON e.pk=c.event_pk WHERE e.id=$1 AND e.state='accepted' AND (c.source_available OR NOT $2) AND c.source_canonical_bytes=e.canonical_bytes")
        .bind::<Binary,_>(event_id.token_bytes().to_vec()).bind::<diesel::sql_types::Bool,_>(require_available).get_result::<AuthorityRow>(conn)
        .await.optional().map_err(PersistenceError::database)?;
    row.map(|row| {
        row.leaf_authorizations
            .map(serde_json::from_value)
            .transpose()
    })
    .transpose()
    .map_err(|error| PersistenceError::Internal(format!("invalid retained MLS authority: {error}")))
}

/// Genesis authority is the exact verified producer, including a retained
/// historical source on replication. It is never selected by today's key.
pub(super) fn genesis_origin(
    request: &soland_storage::EventCommitRequest,
    event: &arkret_wire::Event,
    leaf: &MlsSecurityFrontierLeaf,
    signature_key: &arkret_wire::Base64UrlString,
) -> PersistenceResult<Option<MlsAcceptedLeafAuthorization>> {
    let fail = |error: String| PersistenceError::Conflict(format!("failed_precondition: {error}"));
    let mut authorization = MlsAcceptedLeafAuthorization {
        leaf_index: leaf.leaf_index,
        device_authorize_event_id: None,
        agent_verification_method: None,
        agent_key_authorize_event_id: None,
    };
    if let Ok(device) = arkret_wire::DeviceId::new(leaf.credential_ref.as_str()) {
        let account = leaf
            .actor_id
            .as_account_id()
            .ok_or_else(|| fail("device leaf has no Account".into()))?;
        let reference = if let Some(producer) = &request.historical_producer {
            if !producer.matches_event(event)
                || producer.signer() != &leaf.actor_id
                || arkret_canonical::base64url_encode(producer.key()) != signature_key.as_str()
            {
                return Err(fail(
                    "Genesis differs from its exact historical producer".into(),
                ));
            }
            if let Some(core) = producer.device_authorization() {
                if &core.account_id != account || core.device_id != device {
                    return Err(fail(
                        "Genesis device authority belongs to another endpoint".into(),
                    ));
                }
                Some(core.device_authorize_event_id.clone())
            } else if let Some(control) = producer.account_device_control_authorization() {
                let source = control
                    .history()
                    .authorization(control.authorization_event_id())
                    .ok_or_else(|| {
                        fail("Genesis Control authority lost its exact source".into())
                    })?;
                if control.history().account_id() != account || source.device_id() != &device {
                    return Err(fail(
                        "Genesis Control authority belongs to another endpoint".into(),
                    ));
                }
                Some(control.authorization_event_id().clone())
            } else {
                None
            }
        } else if let Some(gate) = &request.device_revocation_gate {
            if gate.principal_id != account.principal_id
                || gate.station_id != account.station_id
                || gate.device_id != device.as_str()
            {
                return Err(fail(
                    "Genesis device gate belongs to another endpoint".into(),
                ));
            }
            Some(
                EventId::new(gate.target_device_authorize_event_id.clone())
                    .map_err(|error| fail(error.to_string()))?,
            )
        } else {
            None
        };
        let Some(reference) = reference else {
            return Ok(None);
        };
        authorization.device_authorize_event_id = Some(reference);
    } else if let Some(multibase) = leaf
        .credential_ref
        .as_str()
        .strip_prefix("ak:did_core:key:")
    {
        let key = arkret_canonical::decode_ed25519_multibase(multibase)
            .map_err(|error| fail(error.to_string()))?;
        if arkret_canonical::base64url_encode(key) != signature_key.as_str() {
            return Err(fail("pairwise leaf does not bind its key".into()));
        }
    } else {
        return Ok(None);
    }
    authorization
        .endpoint_for_leaf(leaf)
        .map_err(|error| fail(error.to_string()))?;
    Ok(Some(authorization))
}
