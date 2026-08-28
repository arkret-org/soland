use super::*;

#[derive(QueryableByName)]
struct HeadSeqRow {
    #[diesel(sql_type = BigInt)]
    last_seq: i64,
}

#[derive(QueryableByName)]
struct TargetStateRow {
    #[diesel(sql_type = Text)]
    proposal_digest: String,
    #[diesel(sql_type = Text)]
    proposal_event_id: String,
    #[diesel(sql_type = Timestamptz)]
    accepted_at: chrono::DateTime<Utc>,
    #[diesel(sql_type = BigInt)]
    acceptance_seq: i64,
    #[diesel(sql_type = Jsonb)]
    control_proposal_ack: Value,
    #[diesel(sql_type = Jsonb)]
    proposal_decisions: Value,
    #[diesel(sql_type = Bool)]
    decision_overdue: bool,
    #[diesel(sql_type = Nullable<Text>)]
    covering_seal_id: Option<String>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    covered_at: Option<chrono::DateTime<Utc>>,
}

#[derive(QueryableByName)]
struct ReceiptRow {
    #[diesel(sql_type = Jsonb)]
    decision_payload: Value,
}

#[derive(QueryableByName)]
struct CleanupRow {
    #[diesel(sql_type = Text)]
    proposal_digest: String,
    #[diesel(sql_type = Text)]
    proposal_event_id: String,
    #[diesel(sql_type = Text)]
    covering_seal_id: String,
    #[diesel(sql_type = Text)]
    principal_id: arkret_identifiers::DidCoreId,
    #[diesel(sql_type = Text)]
    principal_server_id: arkret_identifiers::DidCoreId,
    #[diesel(sql_type = Text)]
    device_id: String,
    #[diesel(sql_type = Text)]
    target_device_authorize_event_id: String,
    #[diesel(sql_type = BigInt)]
    target_device_generation_ref: i64,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    material_cleanup_completed_at: Option<chrono::DateTime<Utc>>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    mls_obligation_completed_at: Option<chrono::DateTime<Utc>>,
}

#[derive(QueryableByName)]
struct DecisionCommitRow {
    #[diesel(sql_type = Jsonb)]
    control_proposal_ack: Value,
    #[diesel(sql_type = Jsonb)]
    proposal_decisions: Value,
    #[diesel(sql_type = Bool)]
    is_sealed: bool,
}

#[derive(QueryableByName)]
struct ProposalDigestRow {
    #[diesel(sql_type = Text)]
    proposal_digest: String,
}

pub struct PgDeviceRevocationStore {
    pub pool: PgPool,
}

fn generation_as_i64(selector: &DeviceRevocationGateSelector) -> PersistenceResult<i64> {
    i64::try_from(selector.target_device_generation_ref).map_err(|_| {
        PersistenceError::SchemaViolation("device generation exceeds PostgreSQL bigint".to_owned())
    })
}

async fn ensure_head_locked(
    conn: &mut AsyncPgConnection,
    principal_id: &str,
    principal_server_id: &str,
    device_id: &str,
) -> PersistenceResult<i64> {
    sql_query(
        "INSERT INTO device_revocation_linearization_heads \
         (principal_id, principal_server_id, device_id) VALUES ($1, $2, $3) \
         ON CONFLICT DO NOTHING",
    )
    .bind::<Text, _>(principal_id)
    .bind::<Text, _>(principal_server_id)
    .bind::<Text, _>(device_id)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    sql_query(
        "SELECT last_seq FROM device_revocation_linearization_heads \
         WHERE principal_id = $1 AND principal_server_id = $2 AND device_id = $3 \
         FOR UPDATE",
    )
    .bind::<Text, _>(principal_id)
    .bind::<Text, _>(principal_server_id)
    .bind::<Text, _>(device_id)
    .get_result::<HeadSeqRow>(&mut *conn)
    .await
    .map(|row| row.last_seq)
    .map_err(PersistenceError::database)
}

async fn allocate_seq(
    conn: &mut AsyncPgConnection,
    principal_id: &str,
    principal_server_id: &str,
    device_id: &str,
) -> PersistenceResult<u64> {
    ensure_head_locked(conn, principal_id, principal_server_id, device_id).await?;
    let row = sql_query(
        "UPDATE device_revocation_linearization_heads SET last_seq = last_seq + 1, updated_at = now() \
         WHERE principal_id = $1 AND principal_server_id = $2 AND device_id = $3 \
         RETURNING last_seq",
    )
    .bind::<Text, _>(principal_id)
    .bind::<Text, _>(principal_server_id)
    .bind::<Text, _>(device_id)
    .get_result::<HeadSeqRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    u64::try_from(row.last_seq).map_err(|_| {
        PersistenceError::Internal("negative device revocation linearization sequence".to_owned())
    })
}

async fn target_rows(
    conn: &mut AsyncPgConnection,
    selector: &DeviceRevocationGateSelector,
) -> PersistenceResult<Vec<TargetStateRow>> {
    sql_query(
        "SELECT t.proposal_digest, t.proposal_event_id, t.accepted_at, t.acceptance_seq, \
                t.control_proposal_ack, c.proposal_decisions, \
                COALESCE(b.decision_overdue, false) AS decision_overdue, \
                b.seal_id AS covering_seal_id, b.sealed_at AS covered_at \
         FROM device_revocation_targets t \
         JOIN state_control_events c ON c.event_digest = t.proposal_digest \
         LEFT JOIN LATERAL ( \
             SELECT binding.seal_id, binding.sealed_at, \
                    bool_or(binding.decision_overdue) OVER () AS decision_overdue \
             FROM state_seal_control_events binding \
             WHERE binding.event_digest = c.event_digest \
               AND NOT EXISTS (SELECT 1 FROM state_seal_quarantine q \
                               WHERE q.seal_id = binding.seal_id) \
             ORDER BY binding.sealed_at, binding.seal_id LIMIT 1 \
         ) b ON true \
         WHERE t.principal_id = $1 AND t.principal_server_id = $2 AND t.device_id = $3 \
           AND t.target_device_authorize_event_id = $4 \
           AND t.target_device_generation_ref = $5 \
         ORDER BY t.acceptance_seq, t.proposal_digest",
    )
    .bind::<Text, _>(&selector.principal_id)
    .bind::<Text, _>(&selector.principal_server_id)
    .bind::<Text, _>(&selector.device_id)
    .bind::<Text, _>(&selector.target_device_authorize_event_id)
    .bind::<BigInt, _>(generation_as_i64(selector)?)
    .load::<TargetStateRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)
}

fn is_rejected(decisions: &Value) -> bool {
    decisions.as_array().is_some_and(|items| {
        items
            .iter()
            .any(|item| item.get("kind").and_then(Value::as_str) == Some("signed_reject"))
    })
}

fn terminal_reject(
    decisions: &Value,
) -> PersistenceResult<Option<arkret_wire::ControlProposalDecision>> {
    let decisions: Vec<arkret_wire::ControlProposalDecision> =
        serde_json::from_value(decisions.clone()).map_err(|error| {
            PersistenceError::Internal(format!("stored control proposal decisions: {error}"))
        })?;
    Ok(decisions.into_iter().find(|decision| decision.is_reject()))
}

fn status_from_rows(rows: &[TargetStateRow]) -> DeviceRevocationGateStatus {
    if let Some(sealed) = rows.iter().find_map(|row| {
        row.covering_seal_id
            .as_ref()
            .map(|seal| (row.acceptance_seq, &row.proposal_digest, seal))
    }) {
        return DeviceRevocationGateStatus::Revoked {
            covering_seal_id: sealed.2.clone(),
        };
    }
    rows.iter()
        .filter(|row| row.covering_seal_id.is_none() && !is_rejected(&row.proposal_decisions))
        .map(|row| row.proposal_digest.as_str())
        .min()
        .map_or(DeviceRevocationGateStatus::Active, |digest| {
            DeviceRevocationGateStatus::Pending {
                blocking_proposal_digest: digest.to_owned(),
            }
        })
}

pub(crate) async fn gate_status_in_transaction(
    conn: &mut AsyncPgConnection,
    selector: &DeviceRevocationGateSelector,
) -> PersistenceResult<DeviceRevocationGateStatus> {
    ensure_head_locked(
        conn,
        &selector.principal_id,
        &selector.principal_server_id,
        &selector.device_id,
    )
    .await?;
    target_rows(conn, selector)
        .await
        .map(|rows| status_from_rows(&rows))
}

pub(crate) async fn ensure_gate_allowed_in_transaction(
    conn: &mut AsyncPgConnection,
    selector: &DeviceRevocationGateSelector,
) -> PersistenceResult<()> {
    gate_status_in_transaction(conn, selector)
        .await?
        .ensure_allowed()
}

pub(crate) async fn insert_transition_in_transaction(
    conn: &mut AsyncPgConnection,
    transition: &DeviceRevocationTransition,
    accepted_at: chrono::DateTime<Utc>,
) -> PersistenceResult<bool> {
    ensure_head_locked(
        conn,
        &transition.selector.principal_id,
        &transition.selector.principal_server_id,
        &transition.selector.device_id,
    )
    .await?;
    let existing = sql_query(
        "SELECT t.proposal_digest, t.proposal_event_id, t.accepted_at, t.acceptance_seq, \
                t.control_proposal_ack, c.proposal_decisions, \
                COALESCE(b.decision_overdue, false) AS decision_overdue, \
                b.seal_id AS covering_seal_id, b.sealed_at AS covered_at \
         FROM device_revocation_targets t JOIN state_control_events c \
           ON c.event_digest = t.proposal_digest \
         LEFT JOIN LATERAL ( \
             SELECT binding.seal_id, binding.sealed_at, \
                    bool_or(binding.decision_overdue) OVER () AS decision_overdue \
             FROM state_seal_control_events binding \
             WHERE binding.event_digest = c.event_digest \
               AND NOT EXISTS (SELECT 1 FROM state_seal_quarantine q \
                               WHERE q.seal_id = binding.seal_id) \
             ORDER BY binding.sealed_at, binding.seal_id LIMIT 1 \
         ) b ON true \
         WHERE t.proposal_digest = $1 FOR UPDATE OF t, c",
    )
    .bind::<Text, _>(&transition.proposal_digest)
    .get_result::<TargetStateRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    if let Some(existing) = existing {
        let ack: arkret_wire::ControlProposalAck =
            serde_json::from_value(existing.control_proposal_ack).map_err(|error| {
                PersistenceError::Internal(format!("stored revoke Ack: {error}"))
            })?;
        return if existing.proposal_event_id == transition.proposal_event_id
            && ack == transition.control_proposal_ack
        {
            Ok(false)
        } else {
            Err(PersistenceError::Conflict(
                "duplicate_conflict: device revocation target differs".to_owned(),
            ))
        };
    }
    match gate_status_in_transaction(conn, &transition.selector).await? {
        DeviceRevocationGateStatus::Revoked { .. } => {
            return Err(PersistenceError::Conflict("device_revoked".to_owned()));
        }
        DeviceRevocationGateStatus::Active | DeviceRevocationGateStatus::Pending { .. } => {}
        DeviceRevocationGateStatus::AuthorityMismatch
        | DeviceRevocationGateStatus::GenerationMismatch => {
            unreachable!("derived from target rows")
        }
    }
    let live = target_rows(conn, &transition.selector)
        .await?
        .into_iter()
        .filter(|row| !is_rejected(&row.proposal_decisions))
        .count();
    if live >= soland_storage::MAX_DEVICE_REVOCATION_PROPOSALS_PER_GENERATION {
        return Err(PersistenceError::Conflict(
            "schema_violation: device revocation proposal cap exceeded".to_owned(),
        ));
    }
    let acceptance_seq = allocate_seq(
        conn,
        &transition.selector.principal_id,
        &transition.selector.principal_server_id,
        &transition.selector.device_id,
    )
    .await?;
    sql_query(
        "INSERT INTO device_revocation_targets \
         (proposal_digest, principal_id, principal_server_id, device_id, \
          target_device_authorize_event_id, target_device_generation_ref, proposal_event_id, \
          accepted_at, acceptance_seq, control_proposal_ack) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
    )
    .bind::<Text, _>(&transition.proposal_digest)
    .bind::<Text, _>(&transition.selector.principal_id)
    .bind::<Text, _>(&transition.selector.principal_server_id)
    .bind::<Text, _>(&transition.selector.device_id)
    .bind::<Text, _>(&transition.selector.target_device_authorize_event_id)
    .bind::<BigInt, _>(generation_as_i64(&transition.selector)?)
    .bind::<Text, _>(&transition.proposal_event_id)
    .bind::<Timestamptz, _>(accepted_at)
    .bind::<BigInt, _>(i64::try_from(acceptance_seq).map_err(|_| {
        PersistenceError::Internal("device revocation sequence overflow".to_owned())
    })?)
    .bind::<Jsonb, _>(
        serde_json::to_value(&transition.control_proposal_ack).map_err(|error| {
            PersistenceError::Internal(format!("encode device revocation Ack: {error}"))
        })?,
    )
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(true)
}

#[async_trait]
impl DeviceRevocationStore for PgDeviceRevocationStore {
    async fn gate_status(
        &self,
        selector: &DeviceRevocationGateSelector,
    ) -> PersistenceResult<DeviceRevocationGateStatus> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            Ok(gate_status_in_transaction(conn, selector).await?)
        })
        .await
        .map_err(|error| error.into_persistence())
    }

    async fn list_targets(
        &self,
        selector: &DeviceRevocationGateSelector,
    ) -> PersistenceResult<Vec<DeviceRevocationTargetRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = target_rows(&mut conn, selector).await?;
        rows.into_iter()
            .map(|row| {
                let control_proposal_ack: arkret_wire::ControlProposalAck =
                    serde_json::from_value(row.control_proposal_ack).map_err(|error| {
                        PersistenceError::Internal(format!("stored revoke Ack: {error}"))
                    })?;
                let status = if let Some(seal) = row.covering_seal_id {
                    DeviceRevocationTargetStatus::Revoked {
                        covering_seal_id: seal,
                        sealed_at: row.covered_at.ok_or_else(|| {
                            PersistenceError::Internal(
                                "sealed device revocation target lacks sealed_at".to_owned(),
                            )
                        })?,
                    }
                } else if let Some(terminal_decision) = terminal_reject(&row.proposal_decisions)? {
                    DeviceRevocationTargetStatus::Rejected { terminal_decision }
                } else {
                    let decisions: Vec<arkret_wire::ControlProposalDecision> =
                        serde_json::from_value(row.proposal_decisions).map_err(|error| {
                            PersistenceError::Internal(format!(
                                "stored control proposal decisions: {error}"
                            ))
                        })?;
                    let due_at = decisions.last().map_or(
                        control_proposal_ack.decision_due_at,
                        arkret_wire::ControlProposalDecision::decision_due_at,
                    );
                    DeviceRevocationTargetStatus::Pending {
                        decisions,
                        decision_overdue: row.decision_overdue || Utc::now() > due_at,
                    }
                };
                Ok(DeviceRevocationTargetRecord {
                    selector: selector.clone(),
                    proposal_event_id: row.proposal_event_id,
                    proposal_digest: row.proposal_digest,
                    accepted_at: row.accepted_at,
                    acceptance_seq: u64::try_from(row.acceptance_seq).map_err(|_| {
                        PersistenceError::Internal("negative revoke acceptance sequence".to_owned())
                    })?,
                    control_proposal_ack,
                    status,
                })
            })
            .collect()
    }

    async fn linearize_gate(
        &self,
        request: DeviceRevocationGateLinearizationRequest,
    ) -> PersistenceResult<DeviceRevocationGateLinearization> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            ensure_head_locked(
                conn,
                &request.principal_id,
                &request.principal_server_id,
                &request.device_id,
            )
            .await?;
            let existing = sql_query(
                "SELECT decision_payload FROM device_revocation_gate_receipts \
                 WHERE principal_id=$1 AND principal_server_id=$2 AND device_id=$3 \
                   AND action_class=$4 AND intent_digest=$5 FOR UPDATE",
            )
            .bind::<Text, _>(&request.principal_id)
            .bind::<Text, _>(&request.principal_server_id)
            .bind::<Text, _>(&request.device_id)
            .bind::<Text, _>(request.action_class.as_str())
            .bind::<Text, _>(&request.intent_digest)
            .get_result::<ReceiptRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
            if let Some(existing) = existing {
                return Ok(
                    serde_json::from_value(existing.decision_payload).map_err(|error| {
                        PersistenceError::Internal(format!(
                            "stored revocation gate receipt: {error}"
                        ))
                    })?,
                );
            }
            let linearized_at = Utc::now();
            let current = request.origin_current_selector.clone();
            let record = DeviceRevocationGateLinearization {
                status: soland_storage::selector_comparison_status(&request, current.as_ref())
                    .unwrap_or(match current.as_ref() {
                        Some(selector) => gate_status_in_transaction(conn, selector).await?,
                        None => DeviceRevocationGateStatus::AuthorityMismatch,
                    }),
                linearization_seq: allocate_seq(
                    conn,
                    &request.principal_id,
                    &request.principal_server_id,
                    &request.device_id,
                )
                .await?,
                expires_at: linearized_at + chrono::Duration::seconds(30),
                linearized_at,
                request,
            };
            sql_query(
                "INSERT INTO device_revocation_gate_receipts \
                 (principal_id,principal_server_id,device_id,action_class,intent_digest, \
                  decision_payload,linearization_seq,linearized_at,expires_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            )
            .bind::<Text, _>(&record.request.principal_id)
            .bind::<Text, _>(&record.request.principal_server_id)
            .bind::<Text, _>(&record.request.device_id)
            .bind::<Text, _>(record.request.action_class.as_str())
            .bind::<Text, _>(&record.request.intent_digest)
            .bind::<Jsonb, _>(serde_json::to_value(&record).map_err(|error| {
                PersistenceError::Internal(format!("encode revocation gate receipt: {error}"))
            })?)
            .bind::<BigInt, _>(i64::try_from(record.linearization_seq).map_err(|_| {
                PersistenceError::Internal("revocation gate sequence overflow".to_owned())
            })?)
            .bind::<Timestamptz, _>(record.linearized_at)
            .bind::<Timestamptz, _>(record.expires_at)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
            Ok(record)
        })
        .await
        .map_err(|error| error.into_persistence())
    }

    async fn mark_rejected(
        &self,
        _proposal_digest: &str,
        _terminal_decision: &arkret_wire::ControlProposalDecision,
    ) -> PersistenceResult<bool> {
        // The signed decision is the SSOT in state_control_events; gate reads
        // join it directly, so there is no second mutable rejection flag.
        Ok(false)
    }

    async fn commit_decision(
        &self,
        proposal_digest: &str,
        decision: &arkret_wire::ControlProposalDecision,
        policy: arkret_wire::ControlProposalDecisionPolicy,
    ) -> PersistenceResult<ControlProposalDecisionCommitOutcome> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let decision = decision.clone();
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let row = sql_query(
                "SELECT c.control_proposal_ack,c.proposal_decisions, \
                        EXISTS (SELECT 1 FROM state_seal_control_events b \
                                WHERE b.event_digest = c.event_digest) AS is_sealed \
                 FROM state_control_events c WHERE c.event_digest=$1 FOR UPDATE",
            )
            .bind::<Text, _>(proposal_digest)
            .get_result::<DecisionCommitRow>(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
            if row.is_sealed {
                return Err(PersistenceError::Conflict(format!(
                    "failed_precondition: sealed control Event {proposal_digest} cannot receive another proposal decision"
                ))
                .into());
            }
            let ack: arkret_wire::ControlProposalAck =
                serde_json::from_value(row.control_proposal_ack).map_err(|error| {
                    PersistenceError::Internal(format!("stored Control Proposal Ack: {error}"))
                })?;
            let mut decisions: Vec<arkret_wire::ControlProposalDecision> =
                serde_json::from_value(row.proposal_decisions).map_err(|error| {
                    PersistenceError::Internal(format!("stored proposal decisions: {error}"))
                })?;
            if decisions.contains(&decision) {
                return Ok(ControlProposalDecisionCommitOutcome::Duplicate);
            }
            if decisions
                .iter()
                .any(arkret_wire::ControlProposalDecision::is_reject)
            {
                return Err(PersistenceError::Conflict(
                    "failed_precondition: control Event already has a terminal signed rejection"
                        .to_owned(),
                )
                .into());
            }
            decision
                .validate_chain(&ack, &decisions, policy)
                .map_err(|error| PersistenceError::Conflict(error.to_string()))?;
            decisions.push(decision);
            sql_query(
                "UPDATE state_control_events SET proposal_decisions=$2 WHERE event_digest=$1",
            )
            .bind::<Text, _>(proposal_digest)
            .bind::<Jsonb, _>(serde_json::to_value(decisions).map_err(|error| {
                PersistenceError::Internal(format!("encode proposal decisions: {error}"))
            })?)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
            Ok(ControlProposalDecisionCommitOutcome::Accepted)
        })
        .await
        .map_err(|error| error.into_persistence())
    }

    async fn mark_sealed(
        &self,
        proposal_digest: &str,
        covering_seal_id: &str,
        sealed_at: chrono::DateTime<Utc>,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let inserted = stage_sealed_revocation_in_transaction(
                conn,
                proposal_digest,
                covering_seal_id,
                sealed_at,
            )
            .await?;
            Ok(inserted)
        })
        .await
        .map_err(|error| error.into_persistence())
    }

    async fn pending_cleanup_intents(
        &self,
        limit: usize,
    ) -> PersistenceResult<Vec<DeviceRevocationCleanupIntent>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        sql_query(
            "SELECT proposal_digest,proposal_event_id,covering_seal_id,principal_id,principal_server_id,device_id, \
                    target_device_authorize_event_id,target_device_generation_ref,created_at, \
                    material_cleanup_completed_at,mls_obligation_completed_at \
             FROM device_revocation_cleanup_intents \
             WHERE material_cleanup_completed_at IS NULL OR mls_obligation_completed_at IS NULL \
             ORDER BY created_at,proposal_digest LIMIT $1",
        )
        .bind::<BigInt, _>(limit)
        .load::<CleanupRow>(&mut conn)
        .await
        .map_err(PersistenceError::database)?
        .into_iter()
        .map(|row| {
            Ok(DeviceRevocationCleanupIntent {
                proposal_digest: row.proposal_digest,
                proposal_event_id: row.proposal_event_id,
                covering_seal_id: row.covering_seal_id,
                selector: DeviceRevocationGateSelector {
                    principal_id: row.principal_id.into_string(),
                    principal_server_id: row.principal_server_id.into_string(),
                    device_id: row.device_id,
                    target_device_authorize_event_id: row.target_device_authorize_event_id,
                    target_device_generation_ref: u64::try_from(row.target_device_generation_ref)
                        .map_err(|_| PersistenceError::Internal("negative cleanup generation".to_owned()))?,
                },
                created_at: row.created_at,
                material_cleanup_completed_at: row.material_cleanup_completed_at,
                mls_obligation_completed_at: row.mls_obligation_completed_at,
            })
        })
        .collect()
    }

    async fn complete_material_cleanup(
        &self,
        proposal_digest: &str,
        completed_at: chrono::DateTime<Utc>,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "UPDATE device_revocation_cleanup_intents SET material_cleanup_completed_at=$2 \
             WHERE proposal_digest=$1 AND material_cleanup_completed_at IS NULL",
        )
        .bind::<Text, _>(proposal_digest)
        .bind::<Timestamptz, _>(completed_at)
        .execute(&mut conn)
        .await
        .map(|affected| affected > 0)
        .map_err(PersistenceError::database)
    }

    async fn complete_mls_obligation(
        &self,
        proposal_digest: &str,
        completed_at: chrono::DateTime<Utc>,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "UPDATE device_revocation_cleanup_intents SET mls_obligation_completed_at=$2 \
             WHERE proposal_digest=$1 AND mls_obligation_completed_at IS NULL",
        )
        .bind::<Text, _>(proposal_digest)
        .bind::<Timestamptz, _>(completed_at)
        .execute(&mut conn)
        .await
        .map(|affected| affected > 0)
        .map_err(PersistenceError::database)
    }

    async fn complete_mls_obligation_by_event_id(
        &self,
        proposal_event_id: &str,
        completed_at: chrono::DateTime<Utc>,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let rows = sql_query(
                "SELECT proposal_digest FROM device_revocation_cleanup_intents \
                 WHERE proposal_event_id=$1 FOR UPDATE",
            )
            .bind::<Text, _>(proposal_event_id)
            .load::<ProposalDigestRow>(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
            let [row] = rows.as_slice() else {
                return if rows.is_empty() {
                    Ok(false)
                } else {
                    Err(PersistenceError::Conflict(
                        "duplicate_conflict: revoke Event id selects multiple sealed cleanup intents"
                            .to_owned(),
                    )
                    .into())
                };
            };
            let affected = sql_query(
                "UPDATE device_revocation_cleanup_intents SET mls_obligation_completed_at=$2 \
                 WHERE proposal_digest=$1 AND mls_obligation_completed_at IS NULL",
            )
            .bind::<Text, _>(&row.proposal_digest)
            .bind::<Timestamptz, _>(completed_at)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
            Ok(affected > 0)
        })
        .await
        .map_err(|error| error.into_persistence())
    }
}

pub(crate) async fn stage_sealed_revocation_in_transaction(
    conn: &mut AsyncPgConnection,
    proposal_digest: &str,
    covering_seal_id: &str,
    sealed_at: chrono::DateTime<Utc>,
) -> PersistenceResult<bool> {
    let inserted = sql_query(
        "INSERT INTO device_revocation_cleanup_intents \
         (proposal_digest,proposal_event_id,covering_seal_id,principal_id,principal_server_id,device_id, \
          target_device_authorize_event_id,target_device_generation_ref,created_at) \
         SELECT proposal_digest,proposal_event_id,$2,principal_id,principal_server_id,device_id, \
                target_device_authorize_event_id,target_device_generation_ref,$3 \
         FROM device_revocation_targets WHERE proposal_digest=$1 \
         ON CONFLICT (proposal_digest) DO NOTHING",
    )
    .bind::<Text, _>(proposal_digest)
    .bind::<Text, _>(covering_seal_id)
    .bind::<Timestamptz, _>(sealed_at)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if inserted > 0 {
        sql_query(
            "UPDATE devices d SET revoked_at = COALESCE(d.revoked_at, $2), \
                                  updated_at = GREATEST(d.updated_at, $2) \
             FROM device_revocation_targets t \
             WHERE t.proposal_digest=$1 AND d.actor_id=t.principal_id AND d.device_id=t.device_id",
        )
        .bind::<Text, _>(proposal_digest)
        .bind::<Timestamptz, _>(sealed_at)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    }
    Ok(inserted > 0)
}
