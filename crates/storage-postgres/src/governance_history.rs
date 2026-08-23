use arkret_models_collaboration::governance_dependencies::{
    GovernanceDependency, GovernanceDependencySelector, GovernanceRegistryArtifact,
    GovernanceRegistrySnapshot,
};
use arkret_models_collaboration::history_key::{
    HistoryGovernanceTraversalIntent, HistoryGovernanceTraversalRetention,
    MinimalMetadataMlsLeafSignerEvidence, OrganizationRecoveryArchiveReplica,
    OrganizationRecoveryArchiveReplicaOutcome, PeerHistoryTraversalAccess,
    SelfHistoryTraversalAccess,
};
use arkret_models_identity::AuthenticatedSignerResolutionEvidence;
use arkret_wire::{AvailabilityReceipt, Hash, RealmId, SealId};
use soland_storage::{
    ExactWriteOutcome, GovernanceDependencyEdgeRecord, GovernanceDependencySource,
    GovernanceDependencyStore, GovernanceDependencyWrite, HistoricalAgentSignerEvidenceKey,
    HistoryTraversalAccess, HistoryTraversalPin, HistoryTraversalRetainedObject,
    HistoryTraversalRetainedObjectRecord, HistoryTraversalRetentionRecord,
    HistoryTraversalRetentionStore, HistoryTraversalRetentionWrite, PendingRrkAcquisitionInput,
    PendingRrkAcquisitionRecord, PendingRrkAcquisitionState, PendingRrkAcquisitionStore,
    StorageCasOutcome, governance_dependency_canonical, governance_dependency_selector_parts,
    governance_signer_evidence_canonical, historical_agent_signer_evidence_key,
    history_traversal_canonical, history_traversal_retained_object_canonical,
    history_traversal_retained_object_from_json, rrk_archive_authorization_tuple_digest,
    validate_rrk_acceptance,
};

use super::{
    AsyncConnection, AsyncPgConnection, BigInt, Binary, Jsonb, Nullable, OptionalExtension,
    PersistenceError, PersistenceResult, PgPool, PgTransactionError, QueryableByName, RunQueryDsl,
    Text, Timestamptz, Value, async_trait, pg_conn, sql_query,
};

fn stored_hash(value: String, field: &str) -> PersistenceResult<Hash> {
    Hash::new(value).map_err(|error| {
        PersistenceError::Internal(format!("stored {field} digest is invalid: {error}"))
    })
}

fn usize_to_i64(value: usize, field: &str) -> PersistenceResult<i64> {
    i64::try_from(value).map_err(|_| {
        PersistenceError::SchemaViolation(format!("{field} exceeds the PostgreSQL bigint range"))
    })
}

fn u64_to_i64(value: u64, field: &str) -> PersistenceResult<i64> {
    i64::try_from(value).map_err(|_| {
        PersistenceError::SchemaViolation(format!("{field} exceeds the PostgreSQL bigint range"))
    })
}

fn i64_to_u64(value: i64, field: &str) -> PersistenceResult<u64> {
    u64::try_from(value).map_err(|_| {
        PersistenceError::Internal(format!("stored {field} is outside the unsigned range"))
    })
}

pub(crate) async fn put_governance_dependency_exact_in_transaction(
    conn: &mut AsyncPgConnection,
    write: &GovernanceDependencyWrite,
) -> PersistenceResult<ExactWriteOutcome> {
    let canonical = governance_dependency_canonical(&write.item)?;
    let edge_index = u64_to_i64(write.edge_index, "governance dependency edge index")?;
    let (source_kind, source_ref) = write.source.storage_parts();
    let lock_key = format!(
        "governance-dependency:{}:{source_kind}:{source_ref}",
        write.realm_id.as_str()
    );
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind::<Text, _>(&lock_key)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;

    let object_rows = sql_query(
        "INSERT INTO governance_dependency_objects \
            (realm_id, dependency_kind, object_digest, canonical_bytes, object_json) \
         VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
    )
    .bind::<Text, _>(write.realm_id.as_str())
    .bind::<Text, _>(canonical.dependency_kind)
    .bind::<Text, _>(canonical.object_digest.as_str())
    .bind::<Binary, _>(&canonical.canonical_bytes)
    .bind::<Jsonb, _>(&canonical.object_json)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if object_rows == 0 {
        let stored = sql_query(
            "SELECT dependency_kind, object_digest, canonical_bytes, object_json \
             FROM governance_dependency_objects \
             WHERE realm_id = $1 AND dependency_kind = $2 AND object_digest = $3",
        )
        .bind::<Text, _>(write.realm_id.as_str())
        .bind::<Text, _>(canonical.dependency_kind)
        .bind::<Text, _>(canonical.object_digest.as_str())
        .get_result::<DependencyObjectRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        if stored.canonical_bytes != canonical.canonical_bytes
            || stored.object_json != canonical.object_json
        {
            return Err(PersistenceError::Conflict(
                "duplicate_conflict: governance dependency object differs".to_owned(),
            ));
        }
    }

    let (seal_id, event_digest) = match &write.source {
        GovernanceDependencySource::Seal(seal_id) => (Some(seal_id.as_str()), None),
        GovernanceDependencySource::ControlEvent(event_digest) => {
            (None, Some(event_digest.as_str()))
        }
    };
    let edge_rows = sql_query(
        "INSERT INTO governance_dependency_edges \
            (realm_id, seal_id, event_digest, dependency_kind, object_digest, edge_index) \
         VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
    )
    .bind::<Text, _>(write.realm_id.as_str())
    .bind::<Nullable<Text>, _>(seal_id)
    .bind::<Nullable<Text>, _>(event_digest)
    .bind::<Text, _>(canonical.dependency_kind)
    .bind::<Text, _>(canonical.object_digest.as_str())
    .bind::<BigInt, _>(edge_index)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if edge_rows == 0 {
        #[derive(QueryableByName)]
        struct EdgeRow {
            #[diesel(sql_type = Text)]
            dependency_kind: String,
            #[diesel(sql_type = Text)]
            object_digest: String,
            #[diesel(sql_type = BigInt)]
            edge_index: i64,
        }
        let rows = sql_query(
            "SELECT dependency_kind, object_digest, edge_index \
             FROM governance_dependency_edges \
             WHERE realm_id = $1 \
               AND (($2::text IS NOT NULL AND seal_id = $2) \
                 OR ($3::text IS NOT NULL AND event_digest = $3))",
        )
        .bind::<Text, _>(write.realm_id.as_str())
        .bind::<Nullable<Text>, _>(seal_id)
        .bind::<Nullable<Text>, _>(event_digest)
        .load::<EdgeRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        if rows.iter().any(|row| {
            row.edge_index == edge_index
                && row.dependency_kind == canonical.dependency_kind
                && row.object_digest == canonical.object_digest.as_str()
        }) {
            return Ok(ExactWriteOutcome::ExactReplay);
        }
        return Err(PersistenceError::Conflict(
            "duplicate_conflict: governance dependency edge differs".to_owned(),
        ));
    }
    Ok(ExactWriteOutcome::Inserted)
}

#[derive(QueryableByName)]
struct DependencyObjectRow {
    #[diesel(sql_type = Text)]
    dependency_kind: String,
    #[diesel(sql_type = Text)]
    object_digest: String,
    #[diesel(sql_type = Binary)]
    canonical_bytes: Vec<u8>,
    #[diesel(sql_type = Jsonb)]
    object_json: Value,
}

#[derive(QueryableByName)]
struct DependencyEdgeObjectRow {
    #[diesel(sql_type = BigInt)]
    edge_index: i64,
    #[diesel(sql_type = Text)]
    dependency_kind: String,
    #[diesel(sql_type = Text)]
    object_digest: String,
    #[diesel(sql_type = Binary)]
    canonical_bytes: Vec<u8>,
    #[diesel(sql_type = Jsonb)]
    object_json: Value,
}

fn decode_dependency_edge(
    row: DependencyEdgeObjectRow,
) -> PersistenceResult<GovernanceDependencyEdgeRecord> {
    Ok(GovernanceDependencyEdgeRecord {
        edge_index: i64_to_u64(row.edge_index, "governance dependency edge index")?,
        item: decode_dependency(DependencyObjectRow {
            dependency_kind: row.dependency_kind,
            object_digest: row.object_digest,
            canonical_bytes: row.canonical_bytes,
            object_json: row.object_json,
        })?,
    })
}

fn decode_dependency(row: DependencyObjectRow) -> PersistenceResult<GovernanceDependency> {
    let digest = stored_hash(row.object_digest, "governance dependency object")?;
    let object_json = row.object_json;
    let canonical_bytes = arkret_canonical::canonical_json_bytes(&object_json)
        .map_err(|error| PersistenceError::Internal(error.to_string()))?;
    if canonical_bytes != row.canonical_bytes {
        return Err(PersistenceError::Internal(
            "stored governance dependency canonical bytes differ from JSON".to_owned(),
        ));
    }
    let item = match row.dependency_kind.as_str() {
        "availability_receipt" => GovernanceDependency::AvailabilityReceipt {
            selector: GovernanceDependencySelector::AvailabilityReceipt {
                content_digest: digest,
            },
            availability_receipt: serde_json::from_value::<AvailabilityReceipt>(object_json)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
        },
        "authenticated_signer_resolution_evidence" => {
            GovernanceDependency::AuthenticatedSignerResolutionEvidence {
                selector: GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                    content_digest: digest,
                },
                authenticated_signer_resolution_evidence: Box::new(
                    serde_json::from_value::<AuthenticatedSignerResolutionEvidence>(object_json)
                        .map_err(|error| PersistenceError::Internal(error.to_string()))?,
                ),
            }
        }
        "minimal_metadata_mls_leaf_signer_evidence" => {
            GovernanceDependency::MinimalMetadataMlsLeafSignerEvidence {
                selector: GovernanceDependencySelector::MinimalMetadataMlsLeafSignerEvidence {
                    content_digest: digest,
                },
                minimal_metadata_mls_leaf_signer_evidence: serde_json::from_value::<
                    MinimalMetadataMlsLeafSignerEvidence,
                >(object_json)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            }
        }
        "governance_registry_snapshot" => GovernanceDependency::GovernanceRegistrySnapshot {
            selector: GovernanceDependencySelector::GovernanceRegistrySnapshot {
                content_digest: digest,
            },
            governance_registry_snapshot: serde_json::from_value::<GovernanceRegistrySnapshot>(
                object_json,
            )
            .map_err(|error| PersistenceError::Internal(error.to_string()))?,
        },
        "governance_registry_artifact" => {
            let artifact = serde_json::from_value::<GovernanceRegistryArtifact>(object_json)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?;
            if artifact.descriptor.content_digest() != &digest {
                return Err(PersistenceError::Internal(
                    "stored governance artifact descriptor digest differs from its row key"
                        .to_owned(),
                ));
            }
            GovernanceDependency::GovernanceRegistryArtifact {
                selector: GovernanceDependencySelector::GovernanceRegistryArtifact {
                    descriptor: artifact.descriptor.clone(),
                },
                governance_registry_artifact: artifact,
            }
        }
        kind => {
            return Err(PersistenceError::Internal(format!(
                "stored governance dependency kind is invalid: {kind}"
            )));
        }
    };
    governance_dependency_canonical(&item)?;
    Ok(item)
}

async fn load_dependency(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
    kind: &str,
    digest: &Hash,
) -> PersistenceResult<Option<GovernanceDependency>> {
    sql_query(
        "SELECT dependency_kind, object_digest, canonical_bytes, object_json \
         FROM governance_dependency_objects \
         WHERE realm_id = $1 AND dependency_kind = $2 AND object_digest = $3",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(kind)
    .bind::<Text, _>(digest.as_str())
    .get_result::<DependencyObjectRow>(conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .map(decode_dependency)
    .transpose()
}

pub struct PgGovernanceDependencyStore {
    pub pool: PgPool,
}

#[async_trait]
impl GovernanceDependencyStore for PgGovernanceDependencyStore {
    async fn put_unscoped_signer_evidence_exact(
        &self,
        item: GovernanceDependency,
    ) -> PersistenceResult<ExactWriteOutcome> {
        let canonical = governance_signer_evidence_canonical(&item)?;
        let historical_key = historical_agent_signer_evidence_key(&item)?;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let lock_key = format!(
                "governance-unscoped-signer:{}:{}",
                canonical.dependency_kind,
                canonical.object_digest.as_str()
            );
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind::<Text, _>(&lock_key)
                .execute(&mut *conn)
                .await?;
            let inserted = sql_query(
                "INSERT INTO governance_unscoped_signer_evidence \
                    (dependency_kind,object_digest,canonical_bytes,object_json, \
                     historical_agent_id,historical_verification_method,historical_event_id, \
                     historical_event_digest,historical_receiver_service_id) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING",
            )
            .bind::<Text, _>(canonical.dependency_kind)
            .bind::<Text, _>(canonical.object_digest.as_str())
            .bind::<Binary, _>(&canonical.canonical_bytes)
            .bind::<Jsonb, _>(&canonical.object_json)
            .bind::<Nullable<Text>, _>(historical_key.as_ref().map(|key| key.agent_id.as_str()))
            .bind::<Nullable<Text>, _>(
                historical_key
                    .as_ref()
                    .map(|key| key.verification_method.as_str()),
            )
            .bind::<Nullable<Text>, _>(historical_key.as_ref().map(|key| key.event_id.as_str()))
            .bind::<Nullable<Text>, _>(historical_key.as_ref().map(|key| key.event_digest.as_str()))
            .bind::<Nullable<Text>, _>(
                historical_key
                    .as_ref()
                    .map(|key| key.receiver_service_id.as_str()),
            )
            .execute(&mut *conn)
            .await?;
            if inserted == 1 {
                return Ok(ExactWriteOutcome::Inserted);
            }
            let stored = sql_query(
                "SELECT dependency_kind,object_digest,canonical_bytes,object_json \
                 FROM governance_unscoped_signer_evidence \
                 WHERE dependency_kind=$1 AND object_digest=$2",
            )
            .bind::<Text, _>(canonical.dependency_kind)
            .bind::<Text, _>(canonical.object_digest.as_str())
            .get_result::<DependencyObjectRow>(&mut *conn)
            .await
            .optional()?;
            let Some(stored) = stored else {
                return Err(PersistenceError::Conflict(
                    "duplicate_conflict: historical Agent signer evidence tuple differs".to_owned(),
                )
                .into());
            };
            if stored.canonical_bytes != canonical.canonical_bytes
                || stored.object_json != canonical.object_json
            {
                return Err(PersistenceError::Conflict(
                    "duplicate_conflict: unscoped signer evidence differs".to_owned(),
                )
                .into());
            }
            Ok(ExactWriteOutcome::ExactReplay)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn get_unscoped_signer_evidence(
        &self,
        selector: &GovernanceDependencySelector,
    ) -> PersistenceResult<Option<GovernanceDependency>> {
        if !matches!(
            selector,
            GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence { .. }
                | GovernanceDependencySelector::MinimalMetadataMlsLeafSignerEvidence { .. }
        ) {
            return Err(PersistenceError::SchemaViolation(
                "unscoped governance dependency lookup accepts signer evidence only".to_owned(),
            ));
        }
        let (kind, digest) = governance_dependency_selector_parts(selector)?;
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT dependency_kind,object_digest,canonical_bytes,object_json \
             FROM governance_unscoped_signer_evidence \
             WHERE dependency_kind=$1 AND object_digest=$2",
        )
        .bind::<Text, _>(kind)
        .bind::<Text, _>(digest.as_str())
        .get_result::<DependencyObjectRow>(&mut conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(decode_dependency)
        .transpose()
    }

    async fn get_historical_agent_signer_evidence(
        &self,
        key: &HistoricalAgentSignerEvidenceKey,
    ) -> PersistenceResult<Option<GovernanceDependency>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT dependency_kind,object_digest,canonical_bytes,object_json \
             FROM governance_unscoped_signer_evidence \
             WHERE historical_agent_id=$1 AND historical_verification_method=$2 \
               AND historical_event_id=$3 AND historical_event_digest=$4 \
               AND historical_receiver_service_id=$5",
        )
        .bind::<Text, _>(key.agent_id.as_str())
        .bind::<Text, _>(key.verification_method.as_str())
        .bind::<Text, _>(key.event_id.as_str())
        .bind::<Text, _>(key.event_digest.as_str())
        .bind::<Text, _>(key.receiver_service_id.as_str())
        .get_result::<DependencyObjectRow>(&mut conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(decode_dependency)
        .transpose()
    }

    async fn put_realm_object_exact(
        &self,
        realm_id: &RealmId,
        item: GovernanceDependency,
    ) -> PersistenceResult<ExactWriteOutcome> {
        let canonical = governance_dependency_canonical(&item)?;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let lock_key = format!(
                "governance-dependency-object:{}:{}:{}",
                realm_id.as_str(),
                canonical.dependency_kind,
                canonical.object_digest.as_str()
            );
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind::<Text, _>(&lock_key)
                .execute(&mut *conn)
                .await?;
            let inserted = sql_query(
                "INSERT INTO governance_dependency_objects \
                    (realm_id,dependency_kind,object_digest,canonical_bytes,object_json) \
                 VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING",
            )
            .bind::<Text, _>(realm_id.as_str())
            .bind::<Text, _>(canonical.dependency_kind)
            .bind::<Text, _>(canonical.object_digest.as_str())
            .bind::<Binary, _>(&canonical.canonical_bytes)
            .bind::<Jsonb, _>(&canonical.object_json)
            .execute(&mut *conn)
            .await?;
            if inserted == 1 {
                return Ok(ExactWriteOutcome::Inserted);
            }
            let stored = sql_query(
                "SELECT dependency_kind,object_digest,canonical_bytes,object_json \
                 FROM governance_dependency_objects \
                 WHERE realm_id=$1 AND dependency_kind=$2 AND object_digest=$3",
            )
            .bind::<Text, _>(realm_id.as_str())
            .bind::<Text, _>(canonical.dependency_kind)
            .bind::<Text, _>(canonical.object_digest.as_str())
            .get_result::<DependencyObjectRow>(&mut *conn)
            .await?;
            if stored.canonical_bytes != canonical.canonical_bytes
                || stored.object_json != canonical.object_json
            {
                return Err(PersistenceError::Conflict(
                    "duplicate_conflict: governance dependency object differs".to_owned(),
                )
                .into());
            }
            Ok(ExactWriteOutcome::ExactReplay)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn put_exact(
        &self,
        write: GovernanceDependencyWrite,
    ) -> PersistenceResult<ExactWriteOutcome> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            put_governance_dependency_exact_in_transaction(conn, &write)
                .await
                .map_err(Into::into)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn get(
        &self,
        realm_id: &RealmId,
        selector: &GovernanceDependencySelector,
    ) -> PersistenceResult<Option<GovernanceDependency>> {
        let (kind, digest) = governance_dependency_selector_parts(selector)?;
        let mut conn = pg_conn(&self.pool).await?;
        load_dependency(&mut conn, realm_id, kind, &digest).await
    }

    async fn list_for_source(
        &self,
        realm_id: &RealmId,
        source: &GovernanceDependencySource,
    ) -> PersistenceResult<Vec<GovernanceDependencyEdgeRecord>> {
        let (source_kind, source_ref) = source.storage_parts();
        let source_column = match source_kind {
            "seal" => "edge.seal_id",
            "control_event" => "edge.event_digest",
            _ => unreachable!("closed governance dependency source"),
        };
        let mut conn = pg_conn(&self.pool).await?;
        let query = format!(
            "SELECT edge.edge_index, object.dependency_kind, object.object_digest, object.canonical_bytes, \
                    object.object_json \
             FROM governance_dependency_edges edge \
             JOIN governance_dependency_objects object \
               ON object.realm_id = edge.realm_id \
              AND object.dependency_kind = edge.dependency_kind \
              AND object.object_digest = edge.object_digest \
             WHERE edge.realm_id = $1 AND {source_column} = $2 \
             ORDER BY edge.edge_index"
        );
        sql_query(query)
            .bind::<Text, _>(realm_id.as_str())
            .bind::<Text, _>(source_ref)
            .load::<DependencyEdgeObjectRow>(&mut *conn)
            .await
            .map_err(PersistenceError::database)?
            .into_iter()
            .map(decode_dependency_edge)
            .collect()
    }
}

#[derive(QueryableByName)]
struct TraversalRetentionRow {
    #[diesel(sql_type = Text)]
    retention_digest: String,
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    access_kind: String,
    #[diesel(sql_type = Text)]
    retention_kind: String,
    #[diesel(sql_type = Text)]
    access_digest: String,
    #[diesel(sql_type = Jsonb)]
    traversal_intent: Value,
    #[diesel(sql_type = Jsonb)]
    trusted_history_base_basis: Value,
    #[diesel(sql_type = Jsonb)]
    trusted_current_basis: Value,
    #[diesel(sql_type = Jsonb)]
    target_basis: Value,
    #[diesel(sql_type = Text)]
    registry_snapshot_digest: String,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(QueryableByName)]
struct TraversalPinRow {
    #[diesel(sql_type = Text)]
    object_kind: String,
    #[diesel(sql_type = Text)]
    object_ref: String,
    #[diesel(sql_type = Text)]
    object_digest: String,
    #[diesel(sql_type = BigInt)]
    pin_index: i64,
    #[diesel(sql_type = Binary)]
    canonical_bytes: Vec<u8>,
    #[diesel(sql_type = Jsonb)]
    object_json: Value,
}

fn decode_traversal_pin(row: &TraversalPinRow) -> PersistenceResult<HistoryTraversalPin> {
    i64_to_u64(row.pin_index, "history traversal pin index")?;
    let object_digest = stored_hash(row.object_digest.clone(), "history traversal pin object")?;
    match row.object_kind.as_str() {
        "seal" => Ok(HistoryTraversalPin::Seal {
            seal_id: SealId::new(row.object_ref.clone()).map_err(|error| {
                PersistenceError::Internal(format!("stored traversal Seal ID is invalid: {error}"))
            })?,
            object_digest,
        }),
        "control_event" => Ok(HistoryTraversalPin::ControlEvent {
            event_digest: stored_hash(row.object_ref.clone(), "history traversal Control Event")?,
            object_digest,
        }),
        "governance_dependency" => Ok(HistoryTraversalPin::GovernanceDependency {
            selector: serde_json::from_str::<GovernanceDependencySelector>(&row.object_ref)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            object_digest,
        }),
        kind => Err(PersistenceError::Internal(format!(
            "stored history traversal pin kind is invalid: {kind}"
        ))),
    }
}

fn decode_traversal_object(
    row: &TraversalPinRow,
) -> PersistenceResult<HistoryTraversalRetainedObject> {
    let object =
        history_traversal_retained_object_from_json(&row.object_kind, row.object_json.clone())?;
    let canonical = history_traversal_retained_object_canonical(&object).map_err(|error| {
        PersistenceError::Internal(format!(
            "stored history traversal retained object is invalid: {error}"
        ))
    })?;
    if canonical.object_ref != row.object_ref
        || canonical.object_digest.as_str() != row.object_digest
        || canonical.canonical_bytes != row.canonical_bytes
        || canonical.object_json != row.object_json
    {
        return Err(PersistenceError::Internal(
            "stored history traversal retained object columns differ from canonical bytes"
                .to_owned(),
        ));
    }
    Ok(object)
}

pub(crate) async fn load_retention(
    conn: &mut AsyncPgConnection,
    retention_digest: &Hash,
) -> PersistenceResult<Option<HistoryTraversalRetentionRecord>> {
    let Some(row) = sql_query(
        "SELECT retention_digest, realm_id, access_kind, retention_kind, access_digest, \
                traversal_intent, trusted_history_base_basis, trusted_current_basis, \
                target_basis, registry_snapshot_digest, expires_at, created_at \
         FROM history_traversal_retentions WHERE retention_digest = $1",
    )
    .bind::<Text, _>(retention_digest.as_str())
    .get_result::<TraversalRetentionRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    else {
        return Ok(None);
    };
    if row.retention_digest != retention_digest.as_str() {
        return Err(PersistenceError::Internal(
            "stored history traversal retention key differs from query".to_owned(),
        ));
    }
    let access_digest = stored_hash(row.access_digest, "history traversal access")?;
    let access = match row.access_kind.as_str() {
        "request_receipt" => {
            HistoryTraversalAccess::SelfAccess(SelfHistoryTraversalAccess::RequestReceipt {
                request_receipt_digest: access_digest,
            })
        }
        "archive_replica" => {
            HistoryTraversalAccess::SelfAccess(SelfHistoryTraversalAccess::ArchiveReplica {
                archive_replica_digest: access_digest,
            })
        }
        "pending_archive_replica" => {
            HistoryTraversalAccess::PeerAccess(PeerHistoryTraversalAccess::PendingArchiveReplica {
                pending_archive_replica_digest: access_digest,
            })
        }
        kind => {
            return Err(PersistenceError::Internal(format!(
                "stored history traversal access kind is invalid: {kind}"
            )));
        }
    };
    let retained_rows = sql_query(
        "SELECT pin.object_kind, pin.object_ref, pin.object_digest, pin.pin_index, \
                object.canonical_bytes, object.object_json \
         FROM history_traversal_pins pin \
         JOIN history_traversal_retained_objects object \
           ON object.object_kind = pin.object_kind \
          AND object.object_digest = pin.object_digest \
         WHERE pin.retention_digest = $1 ORDER BY pin.pin_index",
    )
    .bind::<Text, _>(retention_digest.as_str())
    .load::<TraversalPinRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let pins = retained_rows
        .iter()
        .map(decode_traversal_pin)
        .collect::<PersistenceResult<Vec<_>>>()?;
    let objects = retained_rows
        .iter()
        .map(decode_traversal_object)
        .collect::<PersistenceResult<Vec<_>>>()?;
    let write = HistoryTraversalRetentionWrite {
        access,
        retention: HistoryGovernanceTraversalRetention {
            traversal_intent: serde_json::from_value::<HistoryGovernanceTraversalIntent>(
                row.traversal_intent,
            )
            .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            traversal_intent_digest: retention_digest.clone(),
        },
        pins,
        objects,
    };
    let canonical = history_traversal_canonical(&write).map_err(|error| {
        PersistenceError::Internal(format!("stored traversal retention is invalid: {error}"))
    })?;
    if row.realm_id != canonical.realm_id.as_str()
        || row.retention_kind != canonical.retention_kind
        || row.trusted_history_base_basis != canonical.trusted_history_base_basis
        || row.trusted_current_basis != canonical.trusted_current_basis
        || row.target_basis != canonical.target_basis
        || row.registry_snapshot_digest != canonical.registry_snapshot_digest.as_str()
        || row.expires_at != canonical.expires_at
    {
        return Err(PersistenceError::Internal(
            "stored traversal retention projections differ from its intent".to_owned(),
        ));
    }
    Ok(Some(HistoryTraversalRetentionRecord {
        write,
        created_at: row.created_at,
    }))
}

pub struct PgHistoryTraversalRetentionStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct TraversalObjectCasRow {
    #[diesel(sql_type = Text)]
    object_ref: String,
    #[diesel(sql_type = Binary)]
    canonical_bytes: Vec<u8>,
    #[diesel(sql_type = Jsonb)]
    object_json: Value,
    #[diesel(sql_type = BigInt)]
    reference_count: i64,
}

#[derive(QueryableByName)]
struct TraversalObjectKeyRow {
    #[diesel(sql_type = Text)]
    object_kind: String,
    #[diesel(sql_type = Text)]
    object_digest: String,
}

#[derive(QueryableByName)]
struct TraversalPinKeyRow {
    #[diesel(sql_type = Text)]
    object_kind: String,
    #[diesel(sql_type = Text)]
    object_ref: String,
    #[diesel(sql_type = Text)]
    object_digest: String,
    #[diesel(sql_type = BigInt)]
    pin_index: i64,
}

#[derive(QueryableByName)]
struct RetentionKeyRow {
    #[diesel(sql_type = Text)]
    retention_digest: String,
}

pub(crate) async fn persist_retention_in_transaction(
    conn: &mut AsyncPgConnection,
    write: &HistoryTraversalRetentionWrite,
) -> Result<ExactWriteOutcome, PgTransactionError> {
    let canonical = history_traversal_canonical(write)?;
    let (access_kind, access_digest) = write.access.storage_parts();
    let lock_key = format!(
        "history-traversal-access:{access_kind}:{}",
        access_digest.as_str()
    );
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind::<Text, _>(&lock_key)
        .execute(&mut *conn)
        .await?;
    let inserted = sql_query(
        "INSERT INTO history_traversal_retentions \
            (retention_digest, realm_id, access_kind, retention_kind, access_digest, \
             traversal_intent, trusted_history_base_basis, trusted_current_basis, \
             target_basis, registry_snapshot_digest, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
         ON CONFLICT DO NOTHING",
    )
    .bind::<Text, _>(write.retention.traversal_intent_digest.as_str())
    .bind::<Text, _>(canonical.realm_id.as_str())
    .bind::<Text, _>(access_kind)
    .bind::<Text, _>(canonical.retention_kind)
    .bind::<Text, _>(access_digest.as_str())
    .bind::<Jsonb, _>(&canonical.traversal_intent_json)
    .bind::<Jsonb, _>(&canonical.trusted_history_base_basis)
    .bind::<Jsonb, _>(&canonical.trusted_current_basis)
    .bind::<Jsonb, _>(&canonical.target_basis)
    .bind::<Text, _>(canonical.registry_snapshot_digest.as_str())
    .bind::<Nullable<Timestamptz>, _>(canonical.expires_at)
    .execute(&mut *conn)
    .await?;
    if inserted == 0 {
        let stored = load_retention(conn, &write.retention.traversal_intent_digest).await?;
        return match stored {
            Some(record)
                if record.write.access == write.access
                    && record.write.retention == write.retention
                    && record.write.pins == write.pins
                    && history_traversal_canonical(&record.write)? == canonical =>
            {
                Ok(ExactWriteOutcome::ExactReplay)
            }
            _ => Err(PersistenceError::Conflict(
                "duplicate_conflict: history traversal retention differs".to_owned(),
            )
            .into()),
        };
    }

    let mut object_locks = canonical
        .retained_objects
        .iter()
        .map(|object| {
            format!(
                "history-retained-object:{}:{}",
                object.object_kind,
                object.object_digest.as_str()
            )
        })
        .collect::<Vec<_>>();
    object_locks.sort_unstable();
    object_locks.dedup();
    for lock_key in object_locks {
        sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind::<Text, _>(&lock_key)
            .execute(&mut *conn)
            .await?;
    }

    for (index, (pin, object)) in write
        .pins
        .iter()
        .zip(&canonical.retained_objects)
        .enumerate()
    {
        let object_inserted = sql_query(
            "INSERT INTO history_traversal_retained_objects \
                (object_kind, object_digest, object_ref, canonical_bytes, object_json, reference_count) \
             VALUES ($1, $2, $3, $4, $5, 1) ON CONFLICT DO NOTHING",
        )
        .bind::<Text, _>(object.object_kind)
        .bind::<Text, _>(object.object_digest.as_str())
        .bind::<Text, _>(&object.object_ref)
        .bind::<Binary, _>(&object.canonical_bytes)
        .bind::<Jsonb, _>(&object.object_json)
        .execute(&mut *conn)
        .await?;
        if object_inserted == 0 {
            let stored = sql_query(
                "SELECT object_ref, canonical_bytes, object_json, reference_count \
                 FROM history_traversal_retained_objects \
                 WHERE object_kind = $1 AND object_digest = $2 FOR UPDATE",
            )
            .bind::<Text, _>(object.object_kind)
            .bind::<Text, _>(object.object_digest.as_str())
            .get_result::<TraversalObjectCasRow>(&mut *conn)
            .await?;
            if stored.object_ref != object.object_ref
                || stored.canonical_bytes != object.canonical_bytes
                || stored.object_json != object.object_json
                || stored.reference_count <= 0
            {
                return Err(PersistenceError::Conflict(
                    "duplicate_conflict: retained object digest has different bytes".to_owned(),
                )
                .into());
            }
            let updated = sql_query(
                "UPDATE history_traversal_retained_objects \
                 SET reference_count = reference_count + 1 \
                 WHERE object_kind = $1 AND object_digest = $2 \
                   AND reference_count < 9223372036854775807",
            )
            .bind::<Text, _>(object.object_kind)
            .bind::<Text, _>(object.object_digest.as_str())
            .execute(&mut *conn)
            .await?;
            if updated != 1 {
                return Err(PersistenceError::Conflict(
                    "retained object reference count exhausted".to_owned(),
                )
                .into());
            }
        }
        let (object_kind, object_ref, object_digest) = pin.storage_parts()?;
        sql_query(
            "INSERT INTO history_traversal_pins \
                (retention_digest, object_kind, object_ref, object_digest, pin_index) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind::<Text, _>(write.retention.traversal_intent_digest.as_str())
        .bind::<Text, _>(object_kind)
        .bind::<Text, _>(&object_ref)
        .bind::<Text, _>(object_digest.as_str())
        .bind::<BigInt, _>(usize_to_i64(index, "history traversal pin index")?)
        .execute(&mut *conn)
        .await?;
    }
    Ok(ExactWriteOutcome::Inserted)
}

pub(crate) async fn append_response_signer_dependencies_in_transaction(
    conn: &mut AsyncPgConnection,
    retention_digest: &Hash,
    record: &arkret_models_collaboration::history_key::HistoryKeyResponseRecord,
    dependencies: &[GovernanceDependency],
) -> Result<(), PgTransactionError> {
    let additions =
        soland_storage::history_response_signer_retained_dependencies(record, dependencies)?;
    append_signer_dependency_additions_in_transaction(conn, retention_digest, additions).await
}

pub(crate) async fn append_lost_signer_dependencies_in_transaction(
    conn: &mut AsyncPgConnection,
    retention_digest: &Hash,
    lost_record: &arkret_models_collaboration::history_key::HistoryKeyResponseLostRecord,
    dependencies: &[GovernanceDependency],
) -> Result<(), PgTransactionError> {
    let additions =
        soland_storage::history_lost_signer_retained_dependencies(lost_record, dependencies)?;
    append_signer_dependency_additions_in_transaction(conn, retention_digest, additions).await
}

async fn append_signer_dependency_additions_in_transaction(
    conn: &mut AsyncPgConnection,
    retention_digest: &Hash,
    additions: Vec<(
        soland_storage::HistoryTraversalPin,
        soland_storage::HistoryTraversalRetainedObject,
    )>,
) -> Result<(), PgTransactionError> {
    let canonical = additions
        .iter()
        .map(|(_, object)| history_traversal_retained_object_canonical(object))
        .collect::<PersistenceResult<Vec<_>>>()?;
    let retained = sql_query(
        "SELECT retention_digest FROM history_traversal_retentions \
         WHERE retention_digest=$1 AND access_kind='request_receipt' FOR UPDATE",
    )
    .bind::<Text, _>(retention_digest.as_str())
    .get_result::<RetentionKeyRow>(&mut *conn)
    .await
    .optional()?
    .ok_or_else(|| {
        PersistenceError::NotFound(
            "history source response traversal retention is unavailable".to_owned(),
        )
    })?;
    if retained.retention_digest != retention_digest.as_str() {
        return Err(PersistenceError::Internal(
            "locked source response retention differs from request".to_owned(),
        )
        .into());
    }
    let existing = sql_query(
        "SELECT object_kind,object_ref,object_digest,pin_index FROM history_traversal_pins \
         WHERE retention_digest=$1 ORDER BY pin_index FOR UPDATE",
    )
    .bind::<Text, _>(retention_digest.as_str())
    .load::<TraversalPinKeyRow>(&mut *conn)
    .await?;
    let mut next_index = match existing.last() {
        Some(row) => row.pin_index.checked_add(1).ok_or_else(|| {
            PersistenceError::Internal("history traversal pin index overflow".to_owned())
        })?,
        None => 0,
    };
    let mut pending = Vec::new();
    for ((pin, object), canonical) in additions.into_iter().zip(canonical) {
        let (kind, object_ref, object_digest) = pin.storage_parts()?;
        if existing.iter().any(|row| {
            row.object_kind == kind
                && row.object_ref == object_ref
                && row.object_digest == object_digest.as_str()
        }) {
            continue;
        }
        pending.push((pin, object, canonical));
    }
    if existing.len() + pending.len() > 4_096 {
        return Err(PersistenceError::SchemaViolation(
            "history traversal retention exceeds 4096 pinned objects".to_owned(),
        )
        .into());
    }
    let mut object_locks = pending
        .iter()
        .map(|(_, _, object)| {
            format!(
                "history-retained-object:{}:{}",
                object.object_kind,
                object.object_digest.as_str()
            )
        })
        .collect::<Vec<_>>();
    object_locks.sort_unstable();
    object_locks.dedup();
    for lock_key in object_locks {
        sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind::<Text, _>(&lock_key)
            .execute(&mut *conn)
            .await?;
    }
    for (pin, _, object) in pending {
        let inserted = sql_query(
            "INSERT INTO history_traversal_retained_objects \
                (object_kind,object_digest,object_ref,canonical_bytes,object_json,reference_count) \
             VALUES ($1,$2,$3,$4,$5,1) ON CONFLICT DO NOTHING",
        )
        .bind::<Text, _>(object.object_kind)
        .bind::<Text, _>(object.object_digest.as_str())
        .bind::<Text, _>(&object.object_ref)
        .bind::<Binary, _>(&object.canonical_bytes)
        .bind::<Jsonb, _>(&object.object_json)
        .execute(&mut *conn)
        .await?;
        if inserted == 0 {
            let stored = sql_query(
                "SELECT object_ref,canonical_bytes,object_json,reference_count \
                 FROM history_traversal_retained_objects \
                 WHERE object_kind=$1 AND object_digest=$2 FOR UPDATE",
            )
            .bind::<Text, _>(object.object_kind)
            .bind::<Text, _>(object.object_digest.as_str())
            .get_result::<TraversalObjectCasRow>(&mut *conn)
            .await?;
            if stored.object_ref != object.object_ref
                || stored.canonical_bytes != object.canonical_bytes
                || stored.object_json != object.object_json
                || stored.reference_count <= 0
            {
                return Err(PersistenceError::Conflict(
                    "duplicate_conflict: retained source evidence digest has different bytes"
                        .to_owned(),
                )
                .into());
            }
            let updated = sql_query(
                "UPDATE history_traversal_retained_objects SET reference_count=reference_count+1 \
                 WHERE object_kind=$1 AND object_digest=$2 \
                   AND reference_count<9223372036854775807",
            )
            .bind::<Text, _>(object.object_kind)
            .bind::<Text, _>(object.object_digest.as_str())
            .execute(&mut *conn)
            .await?;
            if updated != 1 {
                return Err(PersistenceError::Conflict(
                    "retained source evidence reference count exhausted".to_owned(),
                )
                .into());
            }
        }
        let (kind, object_ref, object_digest) = pin.storage_parts()?;
        sql_query(
            "INSERT INTO history_traversal_pins \
                (retention_digest,object_kind,object_ref,object_digest,pin_index) \
             VALUES ($1,$2,$3,$4,$5)",
        )
        .bind::<Text, _>(retention_digest.as_str())
        .bind::<Text, _>(kind)
        .bind::<Text, _>(&object_ref)
        .bind::<Text, _>(object_digest.as_str())
        .bind::<BigInt, _>(next_index)
        .execute(&mut *conn)
        .await?;
        next_index = next_index.checked_add(1).ok_or_else(|| {
            PersistenceError::Internal("history traversal pin index overflow".to_owned())
        })?;
    }
    Ok(())
}

pub(crate) async fn release_retention_in_transaction(
    conn: &mut AsyncPgConnection,
    retention_digest: &Hash,
    required_access_kind: Option<&str>,
) -> Result<bool, PgTransactionError> {
    let retained = sql_query(
        "SELECT retention_digest FROM history_traversal_retentions \
         WHERE retention_digest = $1 AND ($2 IS NULL OR access_kind = $2) FOR UPDATE",
    )
    .bind::<Text, _>(retention_digest.as_str())
    .bind::<Nullable<Text>, _>(required_access_kind)
    .get_result::<RetentionKeyRow>(&mut *conn)
    .await
    .optional()?;
    let Some(retained) = retained else {
        return Ok(false);
    };
    if retained.retention_digest != retention_digest.as_str() {
        return Err(PersistenceError::Internal(
            "locked history traversal retention key differs from query".to_owned(),
        )
        .into());
    }
    let object_keys = sql_query(
        "SELECT DISTINCT object_kind, object_digest FROM history_traversal_pins \
         WHERE retention_digest = $1 ORDER BY object_kind, object_digest",
    )
    .bind::<Text, _>(retention_digest.as_str())
    .load::<TraversalObjectKeyRow>(&mut *conn)
    .await?;
    for key in &object_keys {
        let lock_key = format!(
            "history-retained-object:{}:{}",
            key.object_kind, key.object_digest
        );
        sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind::<Text, _>(&lock_key)
            .execute(&mut *conn)
            .await?;
    }
    sql_query("DELETE FROM history_traversal_pins WHERE retention_digest = $1")
        .bind::<Text, _>(retention_digest.as_str())
        .execute(&mut *conn)
        .await?;
    for key in object_keys {
        let stored = sql_query(
            "SELECT object_ref, canonical_bytes, object_json, reference_count \
             FROM history_traversal_retained_objects \
             WHERE object_kind = $1 AND object_digest = $2 FOR UPDATE",
        )
        .bind::<Text, _>(&key.object_kind)
        .bind::<Text, _>(&key.object_digest)
        .get_result::<TraversalObjectCasRow>(&mut *conn)
        .await
        .optional()?
        .ok_or_else(|| {
            PersistenceError::Internal(
                "history traversal pin references a missing retained object".to_owned(),
            )
        })?;
        if stored.reference_count <= 0 {
            return Err(PersistenceError::Internal(
                "history traversal retained object reference count is invalid".to_owned(),
            )
            .into());
        }
        if stored.reference_count == 1 {
            sql_query(
                "DELETE FROM history_traversal_retained_objects \
                 WHERE object_kind = $1 AND object_digest = $2",
            )
            .bind::<Text, _>(&key.object_kind)
            .bind::<Text, _>(&key.object_digest)
            .execute(&mut *conn)
            .await?;
        } else {
            sql_query(
                "UPDATE history_traversal_retained_objects \
                 SET reference_count = reference_count - 1 \
                 WHERE object_kind = $1 AND object_digest = $2",
            )
            .bind::<Text, _>(&key.object_kind)
            .bind::<Text, _>(&key.object_digest)
            .execute(&mut *conn)
            .await?;
        }
    }
    let deleted = sql_query("DELETE FROM history_traversal_retentions WHERE retention_digest = $1")
        .bind::<Text, _>(retention_digest.as_str())
        .execute(&mut *conn)
        .await?;
    if deleted != 1 {
        return Err(PersistenceError::Internal(
            "locked history traversal retention disappeared before release".to_owned(),
        )
        .into());
    }
    Ok(true)
}

#[async_trait]
impl HistoryTraversalRetentionStore for PgHistoryTraversalRetentionStore {
    async fn persist_exact(
        &self,
        write: HistoryTraversalRetentionWrite,
    ) -> PersistenceResult<ExactWriteOutcome> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            persist_retention_in_transaction(conn, &write).await
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn get(
        &self,
        retention_digest: &Hash,
    ) -> PersistenceResult<Option<HistoryTraversalRetentionRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        load_retention(&mut conn, retention_digest).await
    }

    async fn resolve_retained_object(
        &self,
        retention_digest: &Hash,
        pin: &HistoryTraversalPin,
    ) -> PersistenceResult<Option<HistoryTraversalRetainedObjectRecord>> {
        let (object_kind, object_ref, object_digest) = pin.storage_parts()?;
        let mut conn = pg_conn(&self.pool).await?;
        let row = sql_query(
            "SELECT pin.object_kind, pin.object_ref, pin.object_digest, pin.pin_index, \
                    object.canonical_bytes, object.object_json \
             FROM history_traversal_pins pin \
             JOIN history_traversal_retained_objects object \
               ON object.object_kind = pin.object_kind \
              AND object.object_digest = pin.object_digest \
             WHERE pin.retention_digest = $1 AND pin.object_kind = $2 \
               AND pin.object_ref = $3 AND pin.object_digest = $4",
        )
        .bind::<Text, _>(retention_digest.as_str())
        .bind::<Text, _>(object_kind)
        .bind::<Text, _>(&object_ref)
        .bind::<Text, _>(object_digest.as_str())
        .get_result::<TraversalPinRow>(&mut conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        row.map(|row| {
            let stored_pin = decode_traversal_pin(&row)?;
            if &stored_pin != pin {
                return Err(PersistenceError::Internal(
                    "stored retained object pin differs from exact query".to_owned(),
                ));
            }
            Ok(HistoryTraversalRetainedObjectRecord {
                pin: stored_pin,
                object: decode_traversal_object(&row)?,
                canonical_bytes: row.canonical_bytes,
            })
        })
        .transpose()
    }

    async fn release(&self, retention_digest: &Hash) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        let retention_digest = retention_digest.clone();
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            release_retention_in_transaction(conn, &retention_digest, None).await
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
}

#[derive(QueryableByName)]
struct PendingRrkRow {
    #[diesel(sql_type = Text)]
    acquisition_digest: String,
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Jsonb)]
    effective_scope: Value,
    #[diesel(sql_type = Text)]
    mls_group_id: String,
    #[diesel(sql_type = BigInt)]
    epoch: i64,
    #[diesel(sql_type = Text)]
    recovery_key_id: String,
    #[diesel(sql_type = Text)]
    holder_principal_id: String,
    #[diesel(sql_type = Text)]
    holder_service_id: String,
    #[diesel(sql_type = Text)]
    container_event_ref: String,
    #[diesel(sql_type = Text)]
    archive_tuple_digest: String,
    #[diesel(sql_type = Text)]
    archive_replica_digest: String,
    #[diesel(sql_type = Binary)]
    archive_replica_bytes: Vec<u8>,
    #[diesel(sql_type = Jsonb)]
    archive_replica_json: Value,
    #[diesel(sql_type = Text)]
    retention_digest: String,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = BigInt)]
    attempt_count: i64,
    #[diesel(sql_type = Timestamptz)]
    next_attempt_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<Text>)]
    claim_token: Option<String>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    claim_until: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    ready_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    accepted_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Nullable<BigInt>)]
    archive_sequence: Option<i64>,
    #[diesel(sql_type = Nullable<Binary>)]
    accepted_outcome_bytes: Option<Vec<u8>>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    accepted_outcome_json: Option<Value>,
    #[diesel(sql_type = Nullable<Text>)]
    last_error_code: Option<String>,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
}

fn rrk_realm_id(replica: &OrganizationRecoveryArchiveReplica) -> &RealmId {
    match &replica.archive.effective_scope {
        arkret_wire::HistoryEffectiveScope::Realm { realm_id }
        | arkret_wire::HistoryEffectiveScope::Circle { realm_id, .. } => realm_id,
    }
}

fn canonical_value_bytes<T: serde::Serialize>(value: &T) -> PersistenceResult<(Value, Vec<u8>)> {
    let json = serde_json::to_value(value)
        .map_err(|error| PersistenceError::Internal(error.to_string()))?;
    let bytes = arkret_canonical::canonical_json_bytes(&json)
        .map_err(|error| PersistenceError::Internal(error.to_string()))?;
    Ok((json, bytes))
}

fn decode_pending_rrk(row: PendingRrkRow) -> PersistenceResult<PendingRrkAcquisitionRecord> {
    let acquisition_digest = stored_hash(row.acquisition_digest, "pending RRK acquisition")?;
    let archive_replica_digest =
        stored_hash(row.archive_replica_digest, "pending RRK archive replica")?;
    let archive_replica = serde_json::from_value::<OrganizationRecoveryArchiveReplica>(
        row.archive_replica_json.clone(),
    )
    .map_err(|error| PersistenceError::Internal(error.to_string()))?;
    let (_, expected_replica_bytes) = canonical_value_bytes(&archive_replica)?;
    if expected_replica_bytes != row.archive_replica_bytes {
        return Err(PersistenceError::Internal(
            "stored pending RRK archive replica bytes differ from JSON".to_owned(),
        ));
    }
    let expected_scope = serde_json::to_value(&archive_replica.archive.effective_scope)
        .map_err(|error| PersistenceError::Internal(error.to_string()))?;
    let expected_tuple_digest = rrk_archive_authorization_tuple_digest(&archive_replica)?;
    if row.realm_id != rrk_realm_id(&archive_replica).as_str()
        || row.effective_scope != expected_scope
        || row.mls_group_id != archive_replica.archive.mls_group_id
        || i64_to_u64(row.epoch, "pending RRK epoch")? != archive_replica.archive.epoch
        || row.recovery_key_id != archive_replica.archive.recovery_key_id
        || row.holder_principal_id != archive_replica.archive.holder_principal_id.to_string()
        || row.holder_service_id != archive_replica.archive.holder_service_id.to_string()
        || row.container_event_ref != archive_replica.container_event_ref.as_str()
        || row.archive_tuple_digest != expected_tuple_digest.as_str()
        || row.retention_digest
            != archive_replica
                .history_traversal_retention
                .traversal_intent_digest
                .as_str()
    {
        return Err(PersistenceError::Internal(
            "stored pending RRK projection columns differ from the archive replica".to_owned(),
        ));
    }
    let input = PendingRrkAcquisitionInput {
        acquisition_digest,
        archive_replica_digest,
        archive_replica,
        next_attempt_at: row.next_attempt_at,
    };
    input.validate().map_err(|error| {
        PersistenceError::Internal(format!("stored pending RRK input is invalid: {error}"))
    })?;
    let state = match row.state.as_str() {
        "pending" => PendingRrkAcquisitionState::Pending,
        "ready" => PendingRrkAcquisitionState::Ready,
        "accepted" => PendingRrkAcquisitionState::Accepted,
        state => {
            return Err(PersistenceError::Internal(format!(
                "stored pending RRK state is invalid: {state}"
            )));
        }
    };
    let archive_sequence = row
        .archive_sequence
        .map(|sequence| i64_to_u64(sequence, "RRK archive sequence"))
        .transpose()?;
    if (state == PendingRrkAcquisitionState::Pending) == archive_sequence.is_some() {
        return Err(PersistenceError::Internal(
            "stored pending RRK state and reserved archive sequence differ".to_owned(),
        ));
    }
    let accepted_outcome = match (row.accepted_outcome_json, row.accepted_outcome_bytes) {
        (None, None) => None,
        (Some(json), Some(bytes)) => {
            let outcome =
                serde_json::from_value::<OrganizationRecoveryArchiveReplicaOutcome>(json.clone())
                    .map_err(|error| PersistenceError::Internal(error.to_string()))?;
            let (_, expected_bytes) = canonical_value_bytes(&outcome)?;
            if bytes != expected_bytes
                || row.accepted_at != Some(outcome.accepted_at)
                || row.archive_sequence
                    != Some(u64_to_i64(
                        outcome.archive_sequence,
                        "RRK archive sequence",
                    )?)
            {
                return Err(PersistenceError::Internal(
                    "stored pending RRK accepted outcome projection differs from JSON".to_owned(),
                ));
            }
            validate_rrk_acceptance(&input, &outcome).map_err(|error| {
                PersistenceError::Internal(format!(
                    "stored pending RRK accepted outcome is invalid: {error}"
                ))
            })?;
            Some(outcome)
        }
        _ => {
            return Err(PersistenceError::Internal(
                "stored pending RRK accepted outcome is incomplete".to_owned(),
            ));
        }
    };
    if (state == PendingRrkAcquisitionState::Accepted) != accepted_outcome.is_some() {
        return Err(PersistenceError::Internal(
            "stored pending RRK terminal state and outcome differ".to_owned(),
        ));
    }
    Ok(PendingRrkAcquisitionRecord {
        input,
        state,
        attempt_count: i64_to_u64(row.attempt_count, "pending RRK attempt count")?,
        claim_token: row.claim_token,
        claim_until: row.claim_until,
        ready_at: row.ready_at,
        archive_sequence,
        accepted_outcome,
        last_error_code: row.last_error_code,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

const RRK_SELECT: &str = "acquisition_digest, realm_id, effective_scope, mls_group_id, epoch, recovery_key_id, \
     holder_principal_id, holder_service_id, container_event_ref, archive_tuple_digest, \
     archive_replica_digest, archive_replica_bytes, \
     archive_replica_json, retention_digest, state, attempt_count, next_attempt_at, claim_token, \
     claim_until, ready_at, accepted_at, archive_sequence, accepted_outcome_bytes, \
     accepted_outcome_json, last_error_code, created_at, updated_at";

async fn load_pending_rrk(
    conn: &mut AsyncPgConnection,
    acquisition_digest: &Hash,
) -> PersistenceResult<Option<PendingRrkAcquisitionRecord>> {
    sql_query(format!(
        "SELECT {RRK_SELECT} FROM pending_rrk_acquisitions WHERE acquisition_digest = $1"
    ))
    .bind::<Text, _>(acquisition_digest.as_str())
    .get_result::<PendingRrkRow>(conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .map(decode_pending_rrk)
    .transpose()
}

pub struct PgPendingRrkAcquisitionStore {
    pub pool: PgPool,
}

#[async_trait]
impl PendingRrkAcquisitionStore for PgPendingRrkAcquisitionStore {
    async fn enqueue_exact(
        &self,
        input: PendingRrkAcquisitionInput,
        now: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<ExactWriteOutcome> {
        input.validate()?;
        let (replica_json, replica_bytes) = canonical_value_bytes(&input.archive_replica)?;
        let effective_scope = serde_json::to_value(&input.archive_replica.archive.effective_scope)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?;
        let epoch = u64_to_i64(input.archive_replica.archive.epoch, "pending RRK epoch")?;
        let realm_id = rrk_realm_id(&input.archive_replica).clone();
        let archive_tuple_digest = rrk_archive_authorization_tuple_digest(&input.archive_replica)?;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let inserted = sql_query(
                "INSERT INTO pending_rrk_acquisitions \
                    (acquisition_digest, realm_id, effective_scope, mls_group_id, epoch, \
                     recovery_key_id, holder_principal_id, holder_service_id, \
                     container_event_ref, archive_tuple_digest, archive_replica_digest, \
                     archive_replica_bytes, archive_replica_json, retention_digest, \
                     next_attempt_at, created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $16) \
                 ON CONFLICT DO NOTHING",
            )
            .bind::<Text, _>(input.acquisition_digest.as_str())
            .bind::<Text, _>(realm_id.as_str())
            .bind::<Jsonb, _>(&effective_scope)
            .bind::<Text, _>(&input.archive_replica.archive.mls_group_id)
            .bind::<BigInt, _>(epoch)
            .bind::<Text, _>(&input.archive_replica.archive.recovery_key_id)
            .bind::<Text, _>(
                &input
                    .archive_replica
                    .archive
                    .holder_principal_id
                    .to_string(),
            )
            .bind::<Text, _>(&input.archive_replica.archive.holder_service_id.to_string())
            .bind::<Text, _>(input.archive_replica.container_event_ref.as_str())
            .bind::<Text, _>(archive_tuple_digest.as_str())
            .bind::<Text, _>(input.archive_replica_digest.as_str())
            .bind::<Binary, _>(&replica_bytes)
            .bind::<Jsonb, _>(&replica_json)
            .bind::<Text, _>(
                input
                    .archive_replica
                    .history_traversal_retention
                    .traversal_intent_digest
                    .as_str(),
            )
            .bind::<Timestamptz, _>(input.next_attempt_at)
            .bind::<Timestamptz, _>(now)
            .execute(&mut *conn)
            .await?;
            if inserted != 0 {
                return Ok(ExactWriteOutcome::Inserted);
            }
            match load_pending_rrk(&mut *conn, &input.acquisition_digest).await? {
                Some(record) if record.input == input => Ok(ExactWriteOutcome::ExactReplay),
                _ => Err(PersistenceError::Conflict(
                    "duplicate_conflict: pending RRK acquisition differs".to_owned(),
                )
                .into()),
            }
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn get(
        &self,
        acquisition_digest: &Hash,
    ) -> PersistenceResult<Option<PendingRrkAcquisitionRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        load_pending_rrk(&mut conn, acquisition_digest).await
    }

    async fn list_accepted_for_authority(
        &self,
        effective_scope: &arkret_wire::HistoryEffectiveScope,
        holder_principal_id: &arkret_wire::DidCoreId,
        holder_service_id: &arkret_wire::DidCoreId,
        from_epoch: u64,
        to_epoch: u64,
        limit: usize,
    ) -> PersistenceResult<Vec<PendingRrkAcquisitionRecord>> {
        if from_epoch > to_epoch || !(1..=65_537).contains(&limit) {
            return Err(PersistenceError::SchemaViolation(
                "invalid accepted RRK authority query bounds".to_owned(),
            ));
        }
        let effective_scope = serde_json::to_value(effective_scope)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?;
        let Ok(from_epoch) = i64::try_from(from_epoch) else {
            return Ok(Vec::new());
        };
        let to_epoch = i64::try_from(to_epoch).unwrap_or(i64::MAX);
        let limit = usize_to_i64(limit, "accepted RRK authority query limit")?;
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(format!(
            "SELECT {RRK_SELECT} FROM pending_rrk_acquisitions \
             WHERE state = 'accepted' AND effective_scope = $1 \
               AND holder_principal_id = $2 AND holder_service_id = $3 \
               AND epoch BETWEEN $4 AND $5 \
             ORDER BY epoch, container_event_ref, archive_replica_digest LIMIT $6"
        ))
        .bind::<Jsonb, _>(&effective_scope)
        .bind::<Text, _>(holder_principal_id.as_str())
        .bind::<Text, _>(holder_service_id.as_str())
        .bind::<BigInt, _>(from_epoch)
        .bind::<BigInt, _>(to_epoch)
        .bind::<BigInt, _>(limit)
        .load::<PendingRrkRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter().map(decode_pending_rrk).collect()
    }

    async fn list_accepted_for_archive_query(
        &self,
        query: &arkret_models_collaboration::history_key::OrganizationRecoveryArchiveListQuery,
        holder_principal_id: &arkret_wire::DidCoreId,
        after_archive_sequence: Option<u64>,
        limit: usize,
    ) -> PersistenceResult<Vec<PendingRrkAcquisitionRecord>> {
        query
            .validate()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        if !(1..=4_097).contains(&limit) {
            return Err(PersistenceError::SchemaViolation(
                "invalid accepted RRK archive query limit".to_owned(),
            ));
        }
        let after = u64_to_i64(
            after_archive_sequence.unwrap_or_default(),
            "accepted RRK archive query cursor",
        )?;
        let effective_scope = serde_json::to_value(&query.effective_scope)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?;
        let holder_trusted_basis = serde_json::to_value(&query.holder_trusted_basis)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?;
        let Ok(from_epoch) = i64::try_from(query.from_epoch.unwrap_or_default()) else {
            return Ok(Vec::new());
        };
        let to_epoch = query
            .to_epoch
            .and_then(|epoch| i64::try_from(epoch).ok())
            .unwrap_or(i64::MAX);
        let limit = usize_to_i64(limit, "accepted RRK archive query limit")?;
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(format!(
            "SELECT {RRK_SELECT} FROM pending_rrk_acquisitions \
             WHERE state = 'accepted' AND archive_sequence > $1 \
               AND holder_principal_id = $2 AND effective_scope = $3 \
               AND recovery_key_id = $4 \
               AND archive_replica_json #>> '{{archive,key_agreement_ref}}' = $5 \
               AND archive_replica_json #>> '{{archive,accepted_key_evidence_ref}}' = $6 \
               AND archive_replica_json #> '{{archive,holder_trusted_basis}}' = $7 \
               AND epoch BETWEEN $8 AND $9 \
             ORDER BY archive_sequence LIMIT $10"
        ))
        .bind::<BigInt, _>(after)
        .bind::<Text, _>(holder_principal_id.as_str())
        .bind::<Jsonb, _>(&effective_scope)
        .bind::<Text, _>(&query.recovery_key_id)
        .bind::<Text, _>(query.key_agreement_ref.as_str())
        .bind::<Text, _>(query.accepted_key_evidence_ref.as_str())
        .bind::<Jsonb, _>(&holder_trusted_basis)
        .bind::<BigInt, _>(from_epoch)
        .bind::<BigInt, _>(to_epoch)
        .bind::<BigInt, _>(limit)
        .load::<PendingRrkRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter().map(decode_pending_rrk).collect()
    }

    async fn claim_due(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        claim_token: &str,
        claim_until: chrono::DateTime<chrono::Utc>,
        limit: usize,
    ) -> PersistenceResult<Vec<PendingRrkAcquisitionRecord>> {
        if claim_token.is_empty() || claim_until <= now || !(1..=4_096).contains(&limit) {
            return Err(PersistenceError::SchemaViolation(
                "invalid pending RRK claim bounds".to_owned(),
            ));
        }
        let limit = usize_to_i64(limit, "pending RRK claim limit")?;
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(format!(
            "WITH candidates AS ( \
                SELECT acquisition_digest FROM pending_rrk_acquisitions \
                WHERE state IN ('pending', 'ready') AND next_attempt_at <= $1 \
                  AND (claim_until IS NULL OR claim_until <= $1) \
                  AND attempt_count < 9223372036854775807 \
                ORDER BY next_attempt_at, acquisition_digest \
                FOR UPDATE SKIP LOCKED LIMIT $2 \
             ) \
             UPDATE pending_rrk_acquisitions pending \
             SET claim_token = $3, claim_until = $4, \
                 attempt_count = pending.attempt_count + 1, updated_at = $1 \
             FROM candidates \
             WHERE pending.acquisition_digest = candidates.acquisition_digest \
             RETURNING pending.*"
        ))
        .bind::<Timestamptz, _>(now)
        .bind::<BigInt, _>(limit)
        .bind::<Text, _>(claim_token)
        .bind::<Timestamptz, _>(claim_until)
        .load::<PendingRrkRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter().map(decode_pending_rrk).collect()
    }

    async fn record_retry(
        &self,
        acquisition_digest: &Hash,
        claim_token: &str,
        expected_attempt_count: u64,
        next_attempt_at: chrono::DateTime<chrono::Utc>,
        error_code: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<StorageCasOutcome> {
        if claim_token.is_empty() || error_code.is_empty() {
            return Err(PersistenceError::SchemaViolation(
                "pending RRK retry token and error code must be non-empty".to_owned(),
            ));
        }
        let attempt_count = u64_to_i64(expected_attempt_count, "pending RRK attempt count")?;
        let mut conn = pg_conn(&self.pool).await?;
        let updated = sql_query(
            "UPDATE pending_rrk_acquisitions \
             SET next_attempt_at = $4, claim_token = NULL, claim_until = NULL, \
                 last_error_code = $5, updated_at = $6 \
             WHERE acquisition_digest = $1 AND state IN ('pending', 'ready') \
               AND claim_token = $2 AND attempt_count = $3",
        )
        .bind::<Text, _>(acquisition_digest.as_str())
        .bind::<Text, _>(claim_token)
        .bind::<BigInt, _>(attempt_count)
        .bind::<Timestamptz, _>(next_attempt_at)
        .bind::<Text, _>(error_code)
        .bind::<Timestamptz, _>(now)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        if updated != 0 {
            return Ok(StorageCasOutcome::Applied);
        }
        Ok(
            match load_pending_rrk(&mut conn, acquisition_digest).await? {
                Some(record)
                    if record.attempt_count == expected_attempt_count
                        && record.claim_token.is_none()
                        && record.input.next_attempt_at == next_attempt_at
                        && record.last_error_code.as_deref() == Some(error_code) =>
                {
                    StorageCasOutcome::ExactReplay
                }
                _ => StorageCasOutcome::Mismatch,
            },
        )
    }

    async fn mark_ready(
        &self,
        acquisition_digest: &Hash,
        claim_token: &str,
        expected_attempt_count: u64,
        ready_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<StorageCasOutcome> {
        if claim_token.is_empty() {
            return Err(PersistenceError::SchemaViolation(
                "pending RRK ready claim token must be non-empty".to_owned(),
            ));
        }
        let attempt_count = u64_to_i64(expected_attempt_count, "pending RRK attempt count")?;
        let mut conn = pg_conn(&self.pool).await?;
        let updated = sql_query(
            "UPDATE pending_rrk_acquisitions \
             SET state = 'ready', ready_at = $4, \
                 archive_sequence = nextval('history_rrk_archive_sequence'), \
                 last_error_code = NULL, updated_at = $4 \
             WHERE acquisition_digest = $1 AND state = 'pending' \
               AND claim_token = $2 AND attempt_count = $3",
        )
        .bind::<Text, _>(acquisition_digest.as_str())
        .bind::<Text, _>(claim_token)
        .bind::<BigInt, _>(attempt_count)
        .bind::<Timestamptz, _>(ready_at)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        if updated != 0 {
            return Ok(StorageCasOutcome::Applied);
        }
        Ok(
            match load_pending_rrk(&mut conn, acquisition_digest).await? {
                Some(record)
                    if record.state == PendingRrkAcquisitionState::Ready
                        && record.attempt_count == expected_attempt_count
                        && record.ready_at == Some(ready_at) =>
                {
                    StorageCasOutcome::ExactReplay
                }
                _ => StorageCasOutcome::Mismatch,
            },
        )
    }

    async fn mark_accepted(
        &self,
        acquisition_digest: &Hash,
        claim_token: &str,
        expected_attempt_count: u64,
        outcome: OrganizationRecoveryArchiveReplicaOutcome,
    ) -> PersistenceResult<StorageCasOutcome> {
        if claim_token.is_empty() {
            return Err(PersistenceError::SchemaViolation(
                "pending RRK acceptance claim token must be non-empty".to_owned(),
            ));
        }
        let attempt_count = u64_to_i64(expected_attempt_count, "pending RRK attempt count")?;
        let archive_sequence = u64_to_i64(outcome.archive_sequence, "RRK archive sequence")?;
        let (outcome_json, outcome_bytes) = canonical_value_bytes(&outcome)?;
        let mut conn = pg_conn(&self.pool).await?;
        let current = load_pending_rrk(&mut conn, acquisition_digest).await?;
        if let Some(record) = &current {
            validate_rrk_acceptance(&record.input, &outcome)?;
            if record.state == PendingRrkAcquisitionState::Accepted
                && record.attempt_count == expected_attempt_count
                && record.accepted_outcome.as_ref() == Some(&outcome)
            {
                return Ok(StorageCasOutcome::ExactReplay);
            }
        }
        let updated = sql_query(
            "UPDATE pending_rrk_acquisitions \
             SET state = 'accepted', accepted_at = $4, archive_sequence = $5, \
                 accepted_outcome_bytes = $6, accepted_outcome_json = $7, \
                 claim_token = NULL, claim_until = NULL, last_error_code = NULL, updated_at = $4 \
             WHERE acquisition_digest = $1 AND state = 'ready' \
               AND claim_token = $2 AND attempt_count = $3 AND ready_at <= $4 \
               AND archive_sequence = $5",
        )
        .bind::<Text, _>(acquisition_digest.as_str())
        .bind::<Text, _>(claim_token)
        .bind::<BigInt, _>(attempt_count)
        .bind::<Timestamptz, _>(outcome.accepted_at)
        .bind::<BigInt, _>(archive_sequence)
        .bind::<Binary, _>(&outcome_bytes)
        .bind::<Jsonb, _>(&outcome_json)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        if updated != 0 {
            return Ok(StorageCasOutcome::Applied);
        }
        Ok(
            match load_pending_rrk(&mut conn, acquisition_digest).await? {
                Some(record)
                    if record.state == PendingRrkAcquisitionState::Accepted
                        && record.attempt_count == expected_attempt_count
                        && record.accepted_outcome.as_ref() == Some(&outcome) =>
                {
                    StorageCasOutcome::ExactReplay
                }
                _ => StorageCasOutcome::Mismatch,
            },
        )
    }
}
