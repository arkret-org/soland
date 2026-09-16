use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_models_collaboration::sync_frames::account_sync::{
    MlsWelcomeProjectedDeviceMessage, MlsWelcomeProjectionBinding,
};
use serde_json::Value;
use soland_services::delivery::DeviceMessageState;
use soland_services::events::MlsWelcomeState;
use soland_services::operation_semantics as kinds;
use soland_services::projection::{MlsProjectionEffect, ProjectionEffectView};

use super::*;
use crate::state::AppState;

pub async fn project_accepted_operations_from_device(
    state: &AppState,
    origin: &str,
    source_device_id: &str,
    operations: &[Operation],
) {
    if let Err(error) =
        project_accepted_operations_inner(state, origin, source_device_id, operations, None, None)
            .await
    {
        tracing::error!(%error, "accepted operation projection failed");
    }
}

/// Apply the domain/read-model effects of one canonical Event after its
/// atomic acceptance commit.
///
/// The admission path already evaluated the original signed Event into these
/// cell writes and atomically stored its projection timeline row. Reusing the
/// writes here preserves optional producer fields such as `hlc: None`, actor
/// sequence and the exact signed envelope. It also prevents a second
/// Operation-derived timeline row with the same Event id but a different
/// `received_at`.
pub async fn project_accepted_canonical_event_from_device(
    state: &AppState,
    origin: &str,
    source_device_id: &str,
    operation: &Operation,
    cell_writes: &[arkret_wire::cbs::ProjectedCellWrite],
) {
    if let Err(error) = project_accepted_operations_inner(
        state,
        origin,
        source_device_id,
        std::slice::from_ref(operation),
        Some(cell_writes),
        None,
    )
    .await
    {
        tracing::error!(%error, "accepted canonical projection failed");
    }
}

/// The registry-derived cell writes for an accepted projected Event.
///
/// `event-and-patch.md` §2.4.2 makes the registered reducer contract the only
/// source of a cell write. Projection consumes the accepted Event facts held by
/// `ProjectedEventOperation`; it neither reconstructs an unsigned Event nor
/// rewrites projection context into the signed payload.
///
/// An unprojectable Operation yields no writes, which is fail-closed: the
/// reducer rejects a kind whose contract declares writes when handed none.
fn accepted_operation_cell_writes(
    state: &AppState,
    _origin: &str,
    operation: &Operation,
) -> Vec<arkret_wire::cbs::ProjectedCellWrite> {
    let Some(kind) = kinds::canonical_kind_for_operation(operation) else {
        return Vec::new();
    };
    if !kind.is_reducer_input() {
        return Vec::new();
    }
    let input = match operation.projection_input() {
        Ok(input) => input,
        Err(error) => {
            tracing::error!(
                operation_id = %operation.operation_id,
                %kind,
                %error,
                "accepted operation cannot expose its projection input; \
                 the reducer will see no derived cell write"
            );
            return Vec::new();
        }
    };
    let digest_suite = state
        .projections()
        .realm_digest_suite(operation.realm_id.as_str());
    match arkret_schema::project_registered_operation_writes(&input, digest_suite) {
        Ok(writes) => writes,
        Err(error) => {
            tracing::error!(
                operation_id = %operation.operation_id,
                %kind,
                %error,
                "accepted operation does not project its registered cell writes"
            );
            Vec::new()
        }
    }
}

pub(crate) fn accepted_circle_member_reducer_operation(operation: &Operation) -> Operation {
    let mut contextual = operation.clone();
    if let Some(payload) = contextual.payload.as_object_mut() {
        payload.insert("manage_capability_verified".to_owned(), Value::Bool(true));
    }
    contextual
}

/// Keep receiver time as reducer context without contaminating the closed
/// producer payload consumed by the typed membership gate.
pub(crate) fn accepted_member_state_reducer_operation(operation: &Operation) -> Operation {
    let mut contextual = operation.clone();
    let received_at = contextual
        .payload
        .get("event_received_at")
        .and_then(Value::as_str)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&chrono::Utc));
    if let Some(payload) = contextual.payload.as_object_mut() {
        payload.remove("event_received_at");
    }
    if let Some(received_at) = received_at {
        contextual.created_at = received_at;
    }
    contextual
}

pub(crate) async fn mirror_mls_effect_to_persistence(
    state: &AppState,
    origin: &str,
    source_device_id: &str,
    operation: &Operation,
    effect: &ProjectionEffectView,
) -> Result<(), String> {
    let ProjectionEffectView::Mls(effect) = effect else {
        return Ok(());
    };

    match effect {
        MlsProjectionEffect::KeyPackagePublished { keypackage_id } => {
            let record = state
                .projections()
                .mls_key_package_record(keypackage_id)
                .ok_or_else(|| {
                    format!("MLS KeyPackage effect has no projected row: {keypackage_id}")
                })?;
            if let Err(error) = state.mls_key_packages().store_key_package(&record).await {
                return Err(format!("failed to mirror MLS KeyPackage publish: {error}"));
            }
        }
        MlsProjectionEffect::KeyPackageClaimed {
            keypackage_id,
            group_id,
            intended_realm_id,
            claimed_at,
            ..
        } => {
            if let Err(error) = state
                .mls_key_packages()
                .claim_key_package(soland_services::events::ClaimMlsKeyPackageCommand {
                    id: keypackage_id,
                    target: soland_services::events::ClaimMlsKeyPackageTarget::Group(group_id),
                    intended_realm_id: intended_realm_id.as_deref(),
                    device_authorize_event_id: None,
                    agent_key_authorize_event_id: None,
                    device_revocation_gate: None,
                    claimed_at: *claimed_at,
                    claim_expires_at_unix_ms: operation
                        .payload
                        .get("claim_expires_at_unix_ms")
                        .and_then(Value::as_i64),
                })
                .await
            {
                return Err(format!("failed to mirror MLS KeyPackage claim: {error}"));
            }
        }
        MlsProjectionEffect::WelcomeEnqueued {
            welcome_id,
            recipient_actor_id,
            recipient_device_id,
            recipient_endpoint_verification_method,
            intended_realm_id,
        } => {
            let record = state.projections().mls_welcome_record(
                recipient_actor_id,
                recipient_device_id.as_deref(),
                recipient_endpoint_verification_method.as_deref(),
                intended_realm_id.as_deref(),
                welcome_id,
            );
            let record = record
                .ok_or_else(|| format!("MLS Welcome effect has no projected row: {welcome_id}"))?;
            {
                if let Err(error) = state
                    .mls_key_packages()
                    .enqueue_welcome(record.clone())
                    .await
                {
                    return Err(format!("failed to mirror MLS Welcome enqueue: {error}"));
                }
                if record.recipient_device_id.is_some() {
                    project_mls_welcome_to_device(
                        state,
                        origin,
                        source_device_id,
                        operation,
                        &record,
                        welcome_id,
                    )
                    .await?;
                }
            }
        }
        MlsProjectionEffect::RemoveProposalRecorded => {}
        MlsProjectionEffect::GroupGenesis {
            group_id,
            effective_scope,
            creator_actor_id,
            creator_device_id,
            ..
        } => {
            // `mls_genesis_payload` requires `governance_binding`.
            let binding_value =
                crate::routing::mls::payload_fields::governance_binding(&operation.payload)
                    .cloned()
                    .unwrap_or(Value::Null);
            let Ok(effective_scope) =
                serde_json::from_value::<arkret_wire::ScopeRef>(effective_scope.clone())
            else {
                return Err(
                    "refusing to mirror MLS genesis with invalid effective_scope".to_owned(),
                );
            };
            let Ok(binding) = serde_json::from_value::<
                arkret_models_crypto::MlsGovernanceBindingPayload,
            >(binding_value) else {
                return Err(
                    "refusing to mirror MLS genesis with invalid governance_binding".to_owned(),
                );
            };
            if let Err(error) = state
                .mls_commits()
                .initialize_group(soland_services::events::InitializeMlsGroupCommand {
                    effective_scope: effective_scope.clone(),
                    group_id: group_id.clone(),
                    leader_actor_id: creator_actor_id.clone(),
                    creator_device_id: creator_device_id.clone(),
                    genesis_event_ref: operation.context.event_id.to_string(),
                    governance_binding: binding,
                    committed_at: operation.created_at.timestamp(),
                })
                .await
            {
                return Err(format!("failed to mirror MLS genesis epoch: {error}"));
            }
            bind_circle_mls_group(
                state,
                group_id,
                &serde_json::to_value(&effective_scope).unwrap_or(Value::Null),
                false,
            )
            .await?;
        }
        MlsProjectionEffect::CommitEpochAdvanced {
            group_id,
            effective_scope,
            previous_epoch,
            leader_actor_id,
            ..
        } => {
            // `mls_commit_payload` requires `governance_binding`.
            let binding_value =
                crate::routing::mls::payload_fields::governance_binding(&operation.payload)
                    .cloned()
                    .unwrap_or(Value::Null);
            let Ok(effective_scope) =
                serde_json::from_value::<arkret_wire::ScopeRef>(effective_scope.clone())
            else {
                return Err("refusing to mirror MLS commit with invalid effective_scope".to_owned());
            };
            let Ok(binding) = serde_json::from_value::<
                arkret_models_crypto::MlsGovernanceBindingPayload,
            >(binding_value) else {
                return Err(
                    "refusing to mirror MLS commit with invalid governance_binding".to_owned(),
                );
            };
            if let Err(error) = state
                .mls_commits()
                .advance_epoch(soland_services::events::AdvanceMlsEpochCommand {
                    expected_previous_epoch: *previous_epoch,
                    effective_scope: effective_scope.clone(),
                    group_id: group_id.clone(),
                    leader_actor_id: leader_actor_id.clone(),
                    governance_binding: binding,
                    accepted_commit_ref: operation.context.event_id.to_string(),
                    committed_at: operation.created_at.timestamp(),
                })
                .await
            {
                return Err(format!("failed to mirror MLS commit epoch: {error}"));
            }
            bind_circle_mls_group(
                state,
                group_id,
                &serde_json::to_value(&effective_scope).unwrap_or(Value::Null),
                true,
            )
            .await?;
        }
    }
    Ok(())
}

async fn bind_circle_mls_group(
    state: &AppState,
    group_id: &str,
    effective_scope: &Value,
    clear_pending_removals: bool,
) -> Result<(), String> {
    let cleared = state.projections().bind_circle_mls_group(
        group_id,
        effective_scope,
        clear_pending_removals,
    );
    if !clear_pending_removals || cleared.is_empty() {
        return Ok(());
    }
    let completed_at = chrono::Utc::now();
    let proposal_event_ids = cleared
        .iter()
        .flat_map(|obligation| obligation.membership_frontier.iter())
        .collect::<std::collections::BTreeSet<_>>();
    for proposal_event_id in proposal_event_ids {
        match state
            .persistence()
            .complete_device_revocation_mls_obligation_by_event_id(proposal_event_id, completed_at)
            .await
        {
            Ok(true) => {}
            Ok(false) => tracing::debug!(
                proposal_event_id,
                "cleared MLS obligation was not a device-revocation cleanup task"
            ),
            Err(error) => {
                return Err(format!(
                    "acknowledge device-revocation MLS cleanup {proposal_event_id}: {error}"
                ));
            }
        }
    }
    Ok(())
}

/// After the deterministic reducer mutates the in-memory
/// `ProjectionState::{space_containers,strands,morphs}` maps for a
/// Space-container / Strand / Morph lifecycle event, snapshot the affected entry (under
/// projection lock) and upsert it to the corresponding
/// `SpaceContainerProjectionStore` / `StrandProjectionStore` / `MorphProjectionStore`
/// in persistence. Lock is released BEFORE the persistence write so
/// any backend latency doesn't stall other reducer paths.
///
/// Unknown / unrelated kinds are no-ops. Lookup misses produce no immediate
/// write; reducer-level pending replay applies them once the target is
/// materialized, and the later create/snapshot write-through captures the
/// converged projection.
async fn write_through_projection(state: &AppState, operation: &Operation) -> Result<(), String> {
    use soland_services::projection::ProjectionWriteThroughRecord;

    let Some(snapshot) = state
        .projections()
        .projection_write_through_record(operation)
    else {
        return Ok(());
    };
    let result = match snapshot {
        ProjectionWriteThroughRecord::SpaceContainer(record) => {
            state
                .event_queries()
                .store_space_container_projection(&record)
                .await
        }
        ProjectionWriteThroughRecord::Strand(record) => {
            state.event_queries().store_strand_projection(&record).await
        }
        ProjectionWriteThroughRecord::Morph(record) => {
            state.event_queries().store_morph_projection(&record).await
        }
        ProjectionWriteThroughRecord::Circle(record, members) => {
            state
                .event_queries()
                .store_circle_projection(&record, &members)
                .await
        }
        ProjectionWriteThroughRecord::StrandWatch(record) => {
            state
                .event_queries()
                .store_strand_watch_projection(&record)
                .await
        }
    };
    result.map_err(|error| {
        format!(
            "projection write-through {}: {error}",
            operation.operation_id
        )
    })
}

#[cfg(any(test, feature = "test-support"))]
pub async fn project_accepted_operations(state: &AppState, origin: &str, operations: &[Operation]) {
    if let Err(error) =
        project_accepted_operations_inner(state, origin, "", operations, None, None).await
    {
        tracing::error!(%error, "accepted test operation projection failed");
    }
}

async fn project_accepted_operations_inner(
    state: &AppState,
    origin: &str,
    source_device_id: &str,
    operations: &[Operation],
    canonical_cell_writes: Option<&[arkret_wire::cbs::ProjectedCellWrite]>,
    applied_effect: Option<&ProjectionEffectView>,
) -> Result<(), String> {
    debug_assert!(canonical_cell_writes.is_none() || operations.len() == 1);
    for operation in operations {
        tracing::debug!(
            kind = ?soland_services::operation_semantics::canonical_kind_for_operation(operation),
            realm_id = %operation.realm_id,
            origin = %origin,
            "project_accepted_operations"
        );
        ensure_projected_realm(state, origin, operation).await;
        if kinds::operation_is_message_create(operation) {
            project_federated_message(state, origin, operation).await;
            // AKP-0016 §9.4.5 — derive mention notifications with the agent
            // third-party mention gate.
            if applied_effect.is_none() {
                crate::routing::events::notify::dispatch_message_notifications(state, operation)
                    .await;
            }
        } else if kinds::operation_is_invite_create(operation) {
            project_invite_create_operation(state, operation).await;
        } else if kinds::operation_is_invite_third_party(operation) {
            project_invite_third_party_operation(state, operation).await;
        } else if kinds::operation_is_invite_claim(operation) {
            project_invite_claim_operation(state, operation).await;
        } else if kinds::canonical_kind(operation) == arkret_wire::EventKind::InviteAccept {
            project_invite_accept_operation(state, operation).await;
        } else if kinds::canonical_kind(operation) == arkret_wire::EventKind::InviteCancel {
            project_invite_cancel_operation(state, origin, operation).await;
        } else if kinds::canonical_kind(operation) == arkret_wire::EventKind::InviteRevoke {
            project_invite_revoke_operation(state, origin, operation).await;
        } else if kinds::canonical_kind(operation)
            == arkret_wire::EventKind::RealmPlaintextVisibleServices
        {
            project_plaintext_visible_services_operation(state, operation).await;
        } else if kinds::operation_is_membership(operation)
            || kinds::operation_is_realm_lifecycle(operation)
        {
            project_membership_operation(state, origin, operation).await;
        }
        // MID-3 (R3.1, arkret-spec @ 7157ee8) — persist accepted
        // `ak.member.identity.update` events into the in-memory registry.
        // Reducer-shape validation (segment whitelist, cross-cell guard,
        // digest binding) runs inside `project_member_identity_update`;
        // plaintext Ed25519 proof verification has already run at event
        // ingest, and unsupported proof forms fail closed there.
        if kinds::canonical_kind(operation) == arkret_wire::EventKind::MemberIdentityUpdate {
            project_member_identity_update(state, operation).await;
        }
        if kinds::canonical_kind(operation) == arkret_wire::EventKind::AccountDataSet {
            project_account_data_set(state, origin, source_device_id, operation).await;
        }
        if kinds::canonical_kind(operation) == arkret_wire::EventKind::SelfModerationReport {
            materialize_moderation_report(state, operation).await;
        }
        // Also apply to the deterministic reducer.
        // The canonical `ak.circle.member.state` payload is closed and does
        // not carry executor/capability verdict fields. For the already
        // authenticated sidecar aggregate only, supply those values to the
        // reducer on an internal clone. Persistence, sync, and projection
        // events below continue to use the untouched wire-clean operation.
        let reducer_context_operation = if let Some(contextual) =
            read_cursor_reducer_context_operation(state, operation).await
        {
            Some(contextual)
        } else {
            match kinds::canonical_kind_for_operation(operation) {
                Some(arkret_wire::EventKind::MemberState) => {
                    Some(accepted_member_state_reducer_operation(operation))
                }
                Some(arkret_wire::EventKind::CircleMemberState) => {
                    Some(accepted_circle_member_reducer_operation(operation))
                }
                _ => None,
            }
        };
        let reducer_operation = reducer_context_operation.as_ref().unwrap_or(operation);
        let reducer_effect = if let Some(effect) = applied_effect {
            Some(effect.clone())
        } else if actor_private_read_cursor_matches_origin(origin, source_device_id, operation) {
            let cell_writes = canonical_cell_writes
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| accepted_operation_cell_writes(state, origin, operation));
            if kinds::canonical_kind(operation) == arkret_wire::EventKind::ReadCursorAdvance {
                Some(state.projections().apply_read_cursor(reducer_operation))
            } else {
                Some(state.projections().apply_via_state_model_registry(
                    reducer_operation,
                    &cell_writes,
                    state.hlc(),
                ))
            }
        } else {
            None
        };
        if let Some(effect) = reducer_effect {
            if let ProjectionEffectView::Rejected { reason } = &effect {
                tracing::error!(
                    operation_id = %operation.operation_id,
                    kind = %kinds::canonical_kind(operation),
                    %reason,
                    event_id = %reducer_operation.context.event_id,
                    payload = ?reducer_operation.payload,
                    cell_writes = ?canonical_cell_writes,
                    "invariant violation: durably accepted Event was rejected by the live reducer"
                );
            }
            if kinds::canonical_kind(operation) == arkret_wire::EventKind::CapabilityGrant
                && let ProjectionEffectView::PendingReplayQueued { target_ref, reason } = &effect
            {
                tracing::warn!(
                    operation_id = %operation.operation_id,
                    %target_ref,
                    %reason,
                    "durably accepted capability grant is waiting on an unresolved projection dependency"
                );
            }
            if kinds::canonical_kind(operation) == arkret_wire::EventKind::KeyBackupActiveSeries
                && let ProjectionEffectView::Rejected { reason } = &effect
            {
                tracing::error!(
                    operation_id = %operation.operation_id,
                    %reason,
                    "invariant violation: durably accepted active-series Event was rejected by the live reducer"
                );
                debug_assert!(
                    false,
                    "durably accepted active-series Event rejected by live reducer: {reason}"
                );
            }
            fanout_projection_effect_private_update(state, origin, source_device_id, &effect).await;
            mirror_mls_effect_to_persistence(state, origin, source_device_id, operation, &effect)
                .await?;
            // SOL-ORG-04 — persist an accepted `ak.realm.organization`
            // relationship statement projection durably.
            mirror_realm_organization_effect_to_persistence(state, &effect).await?;
            // P1 — fold the projected capability grant cell back into the
            // SolandAuthzEngine read index. The cell is the source of truth;
            // the engine map is a read-side index maintained by projection
            // (no longer written directly by HTTP handlers).
            refresh_authz_index_from_capability_effect(state, &effect);
        }
        // Write through Space-container/Strand/Morph projection changes to durable
        // persistence. Captures the in-memory projection snapshot
        // (under lock), then upserts to persistence after releasing the
        // lock so any backend latency doesn't block other reducer paths.
        // Mirrors the canonical wire kinds the reducer dispatches into
        // `ProjectionState::{space_containers,strands,morphs}`.
        write_through_projection(state, operation).await?;
        crate::routing::identity::account::project_canonical_direct_binding(state, operation).await;
        if applied_effect.is_none()
            && kinds::canonical_kind(operation) == arkret_wire::EventKind::RelationCreate
        {
            crate::routing::events::notify::dispatch_assignment_notifications(state, operation)
                .await;
        }
        if applied_effect.is_none()
            && kinds::canonical_kind(operation) == arkret_wire::EventKind::StrandUpdate
        {
            crate::routing::events::notify::dispatch_schedule_notifications(state, operation).await;
        }
        // AKP-0016 — mirror agent_participation ceiling changes into the
        // agent_participation_ceiling projection table (read by
        // participation.set / .get ceiling resolution).
        if let Some(record) =
            crate::routing::events::operations::agent_participation_ceiling_record(operation)
            && let Err(error) = state.agent_participations().store_ceiling(record).await
        {
            return Err(format!("store agent participation ceiling: {error}"));
        }
        if canonical_cell_writes.is_none() && applied_effect.is_none() {
            let projected = projection_event_from_operation(operation, Some(origin));
            // Operation-only lanes have no canonical Event acceptance
            // transaction, so they still own projection timeline persistence.
            persist_and_publish_projection_event(state, projected)
                .await
                .map_err(|error| format!("store projection event before publish: {error}"))?;
        }
    }
    Ok(())
}

async fn materialize_moderation_report(state: &AppState, operation: &Operation) {
    if let Err(error) = materialize_moderation_report_record(
        state,
        &operation.context.event_id,
        &operation.payload,
        &operation.context.accepted_scope_ref,
        operation.created_at,
    )
    .await
    {
        tracing::error!(
            %error,
            event_id = %operation.context.event_id,
            "accepted moderation report projection failed"
        );
    }
}

/// Idempotently materialise both report workbench records required by
/// content-moderation.md section 3.1.1 from one accepted report Event.
///
/// The ordinary projection path calls this after Event commit. The dedicated
/// report endpoint also calls it before returning its stored outcome so an
/// exact replay repairs either read model if a prior process stopped between
/// canonical acceptance and projection.
pub(crate) async fn materialize_moderation_report_record(
    state: &AppState,
    event_id: &arkret_identifiers::EventId,
    payload: &Value,
    accepted_scope_ref: &arkret_wire::ScopeRef,
    created_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), String> {
    let report_id = arkret_identifiers::ReportId::from_event_id(event_id);
    let queue_item_id = arkret_identifiers::ModerationQueueItemId::from_event_id(event_id);
    let Some(mut report) = payload.as_object().cloned() else {
        return Err("accepted moderation report payload is not an object".to_owned());
    };
    report.insert("report_id".to_owned(), serde_json::json!(report_id));
    report.insert("event_id".to_owned(), serde_json::json!(event_id));
    report.insert(
        "effective_scope".to_owned(),
        serde_json::json!(accepted_scope_ref),
    );
    if payload
        .get("target_ref")
        .and_then(Value::as_str)
        .is_some_and(|target| target.starts_with("ak:event:"))
    {
        report.insert("target_event_id".to_owned(), payload["target_ref"].clone());
    }
    report.insert("created_at".to_owned(), serde_json::json!(created_at));
    let report = Value::Object(report);
    state
        .governance()
        .append_moderation_report(report.clone())
        .await
        .map_err(|error| format!("store moderation report: {error}"))?;
    let queue_item = serde_json::json!({
        "id": queue_item_id,
        "report": report,
        "status": "submitted",
        "priority": "normal",
        "visibility": "metadata_only",
        "assigned_to": [format!("{}#moderation", state.service_id())],
        "audit_refs": [],
        "created_at": created_at,
    });
    state
        .governance()
        .upsert_moderation_queue_item(queue_item)
        .await
        .map_err(|error| format!("store moderation queue item: {error}"))?;
    Ok(())
}

/// SOL-ORG-04 — persist an accepted `ak.realm.organization` relationship
/// statement. The reducer has already verified (organization side) and
/// projected the row into `ProjectionState::realm_organization_statements`;
/// here we snapshot that row (under lock) and upsert it into the durable
/// `realm_organizations` table keyed by `(realm_id, organization_id,
/// relationship)`.
pub(crate) async fn mirror_realm_organization_effect_to_persistence(
    state: &AppState,
    effect: &ProjectionEffectView,
) -> Result<(), String> {
    let ProjectionEffectView::RealmOrganizationProjected {
        realm_id,
        organization_id,
        relationship,
        ..
    } = effect
    else {
        return Ok(());
    };

    let key = (
        realm_id.clone(),
        organization_id.clone(),
        relationship.clone(),
    );
    let row = {
        let proj = state.projections().snapshot();
        proj.realm_organization_statements.get(&key).cloned()
    };
    let row =
        row.ok_or_else(|| "confirmed RealmOrganization effect has no projected row".to_owned())?;
    let record = soland_services::events::RealmOrganizationStatementRecord {
        realm_id: row.realm_id,
        organization_id: row.organization_id,
        relationship: row.relationship,
        statement_id: row.statement_id,
        status: row.status,
        control_scopes: row.control_scopes,
        issued_at: row.issued_at,
        not_before: row.not_before,
        expires_at: row.expires_at,
        supersedes_statement_id: row.supersedes_statement_id,
        revokes_statement_id: row.revokes_statement_id,
        realm_commit_ref: row.realm_commit_ref,
        proof_digest: row.proof_digest,
        delegation_ref: row.delegation_ref,
        issuer_role: row.issuer_role,
        updated_at: row.updated_at,
    };
    state
        .event_queries()
        .store_realm_organization_statement(&record)
        .await
        .map_err(|error| format!("store RealmOrganization statement: {error}"))
}

async fn project_mls_welcome_to_device(
    state: &AppState,
    origin: &str,
    source_device_id: &str,
    operation: &Operation,
    record: &MlsWelcomeState,
    welcome_id: &str,
) -> Result<(), String> {
    let Some(recipient_device_id) = record.recipient_device_id.as_deref() else {
        return Ok(());
    };
    let Ok(welcome) = operation.typed_payload::<arkret_wire::event_spec::MlsWelcome>() else {
        return Err("accepted MLS Welcome payload is not the typed wire shape".to_owned());
    };
    let sender_device_id = if source_device_id.trim().is_empty() {
        welcome
            .sender_device_id
            .as_ref()
            .map(|device_id| device_id.as_str())
            .unwrap_or_default()
    } else {
        source_device_id
    }
    .trim();
    if sender_device_id.is_empty() {
        return Err(
            "cannot enqueue MLS Welcome device message without sender device id".to_owned(),
        );
    }
    let Some(sender_account_id) = operation.context.sender.as_account_id().cloned() else {
        return Err(
            "cannot enqueue an ordinary MLS Welcome device message without an account sender"
                .to_owned(),
        );
    };

    // The recipient incarnation is frozen by the original KeyPackage source,
    // never inferred from a current device that happens to reuse the same id.
    let package = state
        .mls_key_packages()
        .key_package(&record.key_package_id)
        .await
        .map_err(|error| format!("load MLS Welcome KeyPackage source: {error}"))?
        .ok_or_else(|| "MLS Welcome original KeyPackage source is unavailable".to_owned())?;
    let account = arkret_wire::AccountId::new(
        record
            .recipient_actor_id
            .parse()
            .map_err(|error| format!("MLS Welcome recipient: {error}"))?,
        state.service_core_id().clone(),
    );
    let owner = state
        .identities()
        .account(&account)
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "MLS Welcome recipient Account is unavailable".to_owned())?;
    if package.owner_account_pk != owner.pk
        || package.actor_id != record.recipient_actor_id
        || package.device_id.as_deref() != Some(recipient_device_id)
    {
        return Err(
            "MLS Welcome KeyPackage does not bind the full recipient Account/device".into(),
        );
    }
    let authorize = package
        .device_authorize_event_id
        .as_deref()
        .ok_or_else(|| "MLS Welcome KeyPackage omits original device authorization".to_owned())?
        .parse()
        .map_err(|error| format!("MLS Welcome original authorization: {error}"))?;
    let history =
        crate::routing::identity::device_generation::load_confirmed_device_history(state, &account)
            .await
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "MLS Welcome recipient history is unavailable".to_owned())?;
    let original = history.authorization(&authorize).ok_or_else(|| {
        "MLS Welcome original authorization is not in confirmed history".to_owned()
    })?;
    if original.device_id().as_str() != recipient_device_id {
        return Err("MLS Welcome original authorization names another device".into());
    }
    if !history.is_currently_active(original) {
        // A confirmed closure permanently forbids recreating this instance's
        // destroyed secrets during projection recovery.
        return Ok(());
    }
    let recipient_device_authorization = soland_storage::DeviceRevocationGateSelector {
        principal_id: account.principal_id,
        station_id: account.station_id,
        device_id: recipient_device_id.to_owned(),
        target_device_authorize_event_id: original.authorization_event_id().to_string(),
        target_device_generation_ref: original.authorized_generation_ref(),
    };
    let content = match serde_json::to_value(MlsWelcomeProjectedDeviceMessage {
        sender_account_id,
        sender_device_id: sender_device_id.to_owned(),
        expires_at: welcome.expires_at.to_owned(),
        content: welcome,
        unsigned: MlsWelcomeProjectionBinding {
            source_event_id: operation.context.event_id.to_string(),
            mls_welcome_id: welcome_id.to_owned(),
            key_package_id: record.key_package_id.clone(),
        },
    }) {
        Ok(content) => content,
        Err(error) => {
            return Err(format!(
                "serialize typed MLS Welcome device message: {error}"
            ));
        }
    };
    let message = DeviceMessageState {
        idempotency_key: format!("mls_welcome:{welcome_id}"),
        sender: origin.to_owned(),
        recipient: record.recipient_actor_id.clone(),
        device_id: recipient_device_id.to_owned(),
        recipient_device_authorization,
        position: state.next_to_device_position(),
        content,
        created_at: operation.created_at,
    };
    // The queue transaction checks this original recipient instance again;
    // a concurrent closure cannot be bypassed by replaying the Welcome.
    if let Err(error) = state
        .deliveries()
        .append_device_message(None, message)
        .await
    {
        return Err(format!("enqueue MLS Welcome to-device message: {error}"));
    }
    Ok(())
}

/// P1 — fold a projected capability grant cell back into the
/// `SolandAuthzEngine` read index after the reducer wrote it. Called per
/// accepted capability event. The grant cell
/// (`ak.component.capability.grant.v1`) is the source of truth; this keeps
/// the engine's in-memory index (read by `SolandAuthzEngine::check`) in sync
/// with the projection without HTTP handlers writing it directly.
pub(in crate::routing) fn refresh_authz_index_from_capability_effect(
    state: &AppState,
    effect: &ProjectionEffectView,
) {
    let grant_id = match effect {
        ProjectionEffectView::CapabilityProjected { grant_id } => grant_id,
        _ => return,
    };
    refresh_authz_index_from_capability_grant_id(state, grant_id);
}

pub(in crate::routing) fn refresh_authz_index_from_capability_grant_id(
    state: &AppState,
    grant_id: &str,
) {
    match state.projections().effective_engine_grant(grant_id) {
        Some(grant) => state.authorization().upsert_projected_grant(grant),
        // A revoke-before-grant tombstone has no resolvable body/actions.
        None => state.authorization().mark_projected_grant_revoked(grant_id),
    }
}

fn confirmed_event_cell_writes(
    state: &AppState,
    event: &arkret_wire::Event,
) -> Result<Vec<arkret_wire::cbs::ProjectedCellWrite>, String> {
    state
        .projections()
        .project_accepted_cell_writes_with_digest_suite(
            event,
            event.event_id.digest_suite_code().digest_suite(),
        )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn confirmed_mirror_test_operation(index: u8) -> Operation {
        accepted_test_operation(
            arkret_wire::OperationId::new(format!(
                "ak:operation:0196419b-1000-7000-8000-0000000002{index:02}"
            ))
            .unwrap(),
            arkret_wire::RealmId::new("ak:realm:AZMBgosRorGR60hpKELRWvzusosD1_lNIH_hWSFojM0p")
                .unwrap(),
            "ak:did_core:web:alice.example",
            u64::from(index),
            arkret_wire::EventKind::ContactRequested,
            json!({
                "peer": {"kind": "human", "principal_id": "ak:did_core:web:bob.example"},
                "granted_to_peer_scopes": [],
                "introduction_evidence_digest": format!("sha256:{}", "1".repeat(64))
            }),
            chrono::Utc::now(),
        )
    }

    #[tokio::test]
    async fn confirmed_unit_mirror_failure_publishes_no_member_timeline() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let projected = vec![
            (confirmed_mirror_test_operation(11), Vec::new()),
            (confirmed_mirror_test_operation(12), Vec::new()),
        ];
        let effects = [
            ProjectionEffectView::Ignored,
            ProjectionEffectView::Mls(MlsProjectionEffect::KeyPackagePublished {
                keypackage_id: "missing-projected-key-package".to_owned(),
            }),
        ];
        let error = publish_confirmed_command_unit(&state, &projected, &effects)
            .await
            .unwrap_err();
        assert!(error.contains("MLS KeyPackage effect has no projected row"));
        for (operation, _) in &projected {
            assert!(
                state
                    .event_queries()
                    .projected_event(operation.context.event_id.as_str())
                    .await
                    .unwrap()
                    .is_none(),
                "a later member's mirror failure must suppress the first member's timeline too"
            );
        }
    }

    #[tokio::test]
    async fn confirmed_unit_mirror_phase_reuses_durable_timeline_identity() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let projected = vec![
            (confirmed_mirror_test_operation(13), Vec::new()),
            (confirmed_mirror_test_operation(14), Vec::new()),
        ];
        let effects = [ProjectionEffectView::Ignored, ProjectionEffectView::Ignored];
        for _ in 0..2 {
            publish_confirmed_command_unit(&state, &projected, &effects)
                .await
                .unwrap();
        }
        let rows = state
            .event_queries()
            .projected_events_for_realm(projected[0].0.realm_id.as_str())
            .await
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert!(projected.iter().all(|(operation, _)| {
            rows.iter()
                .any(|row| row.event_id == operation.context.event_id.as_str())
        }));
    }

    #[tokio::test]
    async fn moderation_report_materialization_is_complete_and_idempotent() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let event_id =
            arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x42; 32]);
        let realm_id = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x24; 32],
        ));
        let scope = arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        };
        let created_at = chrono::DateTime::parse_from_rfc3339("2026-09-01T12:00:00.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let payload = json!({
            "realm_id": realm_id,
            "target_ref": event_id,
            "report_reason_code": "spam",
            "reporter_id": "ak:did_core:web:alice.example",
            "provenance": "self"
        });

        for _ in 0..2 {
            materialize_moderation_report_record(&state, &event_id, &payload, &scope, created_at)
                .await
                .unwrap();
        }

        let reports = state.governance().moderation_reports().await.unwrap();
        let queue = state.governance().moderation_queue_items().await.unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(queue.len(), 1);
        assert_eq!(reports[0]["event_id"], json!(event_id));
        assert_eq!(queue[0]["report"], reports[0]);
        assert_eq!(queue[0]["status"], "submitted");
    }

    #[tokio::test]
    async fn foreign_device_history_cannot_pollute_the_local_account_directory() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let account = arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:foreign.example").unwrap(),
        );
        assert!(
            crate::routing::identity::device_generation::load_confirmed_device_history(
                &state, &account
            )
            .await
            .is_err()
        );
        assert!(
            state
                .identities()
                .find_device(soland_services::identity::FindDeviceQuery {
                    actor_id: account.principal_id.to_string(),
                    device_id: "ak:device:01904100-0000-7000-8000-000000000001".into(),
                })
                .await
                .unwrap()
                .is_none()
        );
    }

    fn accepted_test_operation(
        operation_id: arkret_identifiers::OperationId,
        realm_id: arkret_identifiers::RealmId,
        actor: &str,
        actor_seq: u64,
        kind: arkret_wire::EventKind,
        payload: serde_json::Value,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> arkret_event_draft::ProjectedEventOperation {
        let event = crate::test_event::raw_event_at(
            kind.as_str(),
            arkret_wire::ScopeRef::Realm { realm_id },
            arkret_identifiers::DidCoreId::new(actor.to_owned()).unwrap(),
            actor_seq,
            arkret_identifiers::Hlc::new(format!("019041000000-{actor_seq:04x}-00000003")).unwrap(),
            payload,
            created_at,
        )
        .unwrap();
        arkret_event_draft::ProjectedEventOperation::from_accepted_event(
            operation_id,
            arkret_wire::OperationKind::Create,
            None,
            &event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn canonical_no_hlc_projection_does_not_restate_or_append_synthetic_timeline() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let actor = arkret_identifiers::Did::new("did:web:alice.example".to_owned()).unwrap();
        let actor_core = arkret_wire::project_did_to_core_id(&actor).unwrap();
        let realm_id = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x32; 32],
        ));
        let created_at = chrono::DateTime::parse_from_rfc3339("2026-08-09T02:00:00.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let mut event = crate::test_event::raw_event_at(
            arkret_wire::EventKind::ContactRequested.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            actor_core.clone(),
            8,
            arkret_identifiers::Hlc::new("019041000000-0000-a13f9c2e").unwrap(),
            json!({
                "peer": {"kind": "human", "principal_id": "ak:did_core:web:bob.example"},
                "granted_to_peer_scopes": [],
                "introduction_evidence_digest": format!("sha256:{}", "1".repeat(64))
            }),
            created_at,
        )
        .unwrap();
        event.hlc = None;
        event.event_id = event
            .derive_event_id_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        let cell_writes = state
            .projections()
            .project_accepted_cell_writes(&event)
            .unwrap();
        assert_eq!(cell_writes.len(), 1);

        let operation = arkret_event_draft::ProjectedEventOperation::from_accepted_event(
            arkret_identifiers::OperationId::new(
                "ak:operation:019a0000-0000-7000-8000-000000000008".to_owned(),
            )
            .unwrap(),
            arkret_wire::OperationKind::Create,
            None,
            &event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        assert!(operation.context.hlc.is_none());

        project_accepted_canonical_event_from_device(
            &state,
            actor_core.as_str(),
            "ak:device:019a0000-0000-7000-8000-000000000008",
            &operation,
            &cell_writes,
        )
        .await;

        // The Contact write is still pending until its successor Seal. This
        // live lane receives the already-validated writes for domain effects;
        // it must not invent a second Event/timeline record while doing so.
        assert!(
            state
                .event_queries()
                .projected_events_for_realm(realm_id.as_str())
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn accepted_circle_member_context_only_adds_verified_capability() {
        let operation = accepted_test_operation(
            arkret_identifiers::OperationId::new(
                "ak:operation:0196419b-1000-7000-8000-000000000202".to_owned(),
            )
            .unwrap(),
            arkret_identifiers::RealmId::new(
                "ak:realm:AZMBgosRorGR60hpKELRWvzusosD1_lNIH_hWSFojM0p".to_owned(),
            )
            .unwrap(),
            "ak:did_core:web:admin.example",
            2,
            arkret_wire::EventKind::CircleMemberState,
            json!({
                "circle_id": "ak:circle:Acz03N1u4b-3h3OIv0LXsw-CHe-rsMKeWw7ZvA-ohkgx",
                "member_id": arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                    arkret_wire::DidCoreId::new("ak:did_core:web:agent.example").unwrap(), crate::test_event::station_id(),
                )),
                "membership": "join"
            }),
            chrono::Utc::now(),
        );

        let contextual = accepted_circle_member_reducer_operation(&operation);

        assert!(operation.payload.get("sender").is_none());
        assert!(
            operation
                .payload
                .get("manage_capability_verified")
                .is_none()
        );
        assert!(contextual.payload.get("sender").is_none());
        assert_eq!(contextual.payload["manage_capability_verified"], true);
    }

    #[test]
    fn accepted_member_state_context_preserves_received_at_outside_typed_payload() {
        let mut operation = accepted_test_operation(
            arkret_identifiers::OperationId::new(
                "ak:operation:0196419b-1000-7000-8000-000000000203".to_owned(),
            )
            .unwrap(),
            arkret_identifiers::RealmId::new(
                "ak:realm:AZMBgosRorGR60hpKELRWvzusosD1_lNIH_hWSFojM0p".to_owned(),
            )
            .unwrap(),
            "ak:did_core:web:member.example",
            3,
            arkret_wire::EventKind::MemberState,
            json!({
                "realm_id": "ak:realm:AZMBgosRorGR60hpKELRWvzusosD1_lNIH_hWSFojM0p",
                "member_id": arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                    arkret_wire::DidCoreId::new("ak:did_core:web:member.example").unwrap(), crate::test_event::station_id(),
                )),
                "membership": "join"
            }),
            chrono::Utc::now(),
        );
        operation.payload["event_received_at"] = json!("2026-07-07T05:20:58.398Z");
        let authored_at = operation.created_at;

        let contextual = accepted_member_state_reducer_operation(&operation);

        assert!(operation.payload.get("event_received_at").is_some());
        assert!(contextual.payload.get("event_received_at").is_none());
        assert_ne!(contextual.created_at, authored_at);
        assert_eq!(
            arkret_canonical::format_timestamp_canonical(contextual.created_at),
            "2026-07-07T05:20:58.398Z"
        );
        contextual
            .typed_payload::<arkret_wire::event_spec::MemberState>()
            .expect("closed typed membership payload");
    }

    #[test]
    fn confirmed_capability_grant_reprojection_uses_authority_resolver() {
        let projection = soland_domain::reducer::ProjectionState::new();
        let realm_id = arkret_wire::RealmId::new(
            "ak:realm:Ac-UY3Pau13QQGFsa1i0Ncx61I9bOu86K1F-dM8J34tC".to_owned(),
        )
        .unwrap();
        let issuer = arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let subject = arkret_wire::DidCoreId::new("ak:did_core:web:agent.example").unwrap();
        let event = crate::test_event::raw_event(
            arkret_wire::EventKind::CapabilityGrant.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            issuer.clone(),
            1,
            arkret_wire::Hlc::new("01980b44cc00-0000-aabbcce3").unwrap(),
            json!({
                "grant": {
                    "schema": "ak.schema.capability.v1",
                    "realm_id": realm_id,
                    "issuer_id": arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                        issuer,
                        crate::test_event::station_id(),
                    )),
                    "subject": arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                        subject,
                        crate::test_event::station_id(),
                    )),
                    "actions": ["ak.realm.admin"],
                    "resources": [{
                        "kind": "realm",
                        "realm_id": realm_id,
                        "match_scope": "realm_wide"
                    }],
                    "issued_at": "2026-08-25T00:00:00.000Z",
                    "issuer_authority_refs": [{
                        "kind": "realm_root",
                        "realm_id": realm_id,
                        "cell_ref": arkret_wire::REALM_AUTHORITY_ROOT_CELL,
                        "controller_epoch_at_issuance": 0,
                        "authority_generation": 0
                    }]
                }
            }),
        )
        .unwrap();

        assert!(
            arkret_schema::project_registered_cell_writes(
                &event,
                arkret_canonical::DigestSuite::Sha256,
            )
            .is_err(),
            "schema-only replay must remain fail-closed without authority context",
        );
        let writes = projection
            .project_registered_cell_writes(&event, arkret_canonical::DigestSuite::Sha256)
            .expect("confirmed replay supplies ProjectionState authority context");
        assert_eq!(writes.len(), 1);
        let arkret_wire::cbs::ProjectedOp::Direct(op) = &writes[0].op else {
            panic!("capability grant must project a direct OR-Set add");
        };
        assert_eq!(
            op.value.as_ref().unwrap()["grant"]["authority_depth"],
            json!(1),
        );
    }
}

/// Publish only exact locally confirmed command units, preserving member order.
/// Domain state is installed atomically before any derived mirror or timeline.
pub(crate) async fn publish_confirmed_seal_commands(
    state: &AppState,
    seal: &arkret_wire::Seal,
) -> Result<(), String> {
    crate::routing::identity::device_generation::recover_confirmed_device_projection(
        state,
        &seal.realm_id,
    )
    .await?;
    if seal.predecessor_ref.is_none() {
        return Ok(());
    }
    if state
        .projections()
        .seal_by_id(&seal.id)
        .await
        .map_err(|error| error.to_string())?
        .as_ref()
        != Some(seal)
    {
        return Err("command publication requires the exact durable Seal".into());
    }
    let _publication = state.projections().confirmed_projection_guard().await;
    let recovered_metadata = state
        .recover_confirmed_metadata_projection(&seal.realm_id)
        .await?;
    let confirmed = state
        .projections()
        .confirmed_command_events(&seal.realm_id)
        .await
        .map_err(|error| error.to_string())?
        .into_iter()
        .map(|event| (event.event_id.event_digest(), event))
        .collect::<std::collections::BTreeMap<_, _>>();
    // Validate the whole committed selection before touching runtime caches.
    // Contacts are queried directly through their durable port; only Consent
    // has a cached current cell map to reload after the transaction commits.
    let committed_events = seal
        .command_results
        .iter()
        .filter(|result| result.outcome == arkret_wire::CommandOutcome::Committed)
        .flat_map(|result| &result.unit_event_digests)
        .map(|digest| {
            confirmed
                .get(digest)
                .ok_or_else(|| "Seal command is outside the confirmed prefix".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if committed_events.iter().any(|event| {
        matches!(
            event.kind,
            arkret_wire::EventKind::ConsentGrant | arkret_wire::EventKind::ConsentRevoke
        )
    }) {
        state
            .consents()
            .hydrate_runtime()
            .await
            .map_err(|error| format!("reload confirmed consent cells: {error}"))?;
    }
    if committed_events
        .iter()
        .any(|event| event.kind == arkret_wire::EventKind::ContactTombstone)
    {
        state
            .contacts()
            .hydrate_runtime()
            .await
            .map_err(|error| format!("reload confirmed Contact invite policy: {error}"))?;
    }
    for result in &seal.command_results {
        if result.outcome != arkret_wire::CommandOutcome::Committed {
            continue;
        }
        let events = result
            .unit_event_digests
            .iter()
            .map(|digest| {
                confirmed
                    .get(digest)
                    .ok_or_else(|| "Seal command is outside the confirmed prefix".to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?;
        if !result.unit_event_digests.is_empty()
            && result
                .unit_event_digests
                .iter()
                .all(|id| recovered_metadata.contains(id))
        {
            // These are replayable wake-up hints for durable timeline rows,
            // not user notifications or evidence of completion. Event identity
            // makes a repeated hint harmless after an exact retry.
            for event in &events {
                if let Some(row) = state
                    .event_queries()
                    .projected_event(event.event_id.as_str())
                    .await
                    .map_err(|error| error.to_string())?
                {
                    let _ =
                        state.publish_event_notification(crate::state::EventNotification::event(
                            row.realm_id.clone(),
                            row.event_id.clone(),
                            projection_event_json(&row),
                        ));
                }
            }
            continue;
        }
        let mut all_published = true;
        for event in &events {
            all_published &= state
                .event_queries()
                .projected_event(event.event_id.as_str())
                .await
                .map_err(|error| error.to_string())?
                .is_some();
        }
        if all_published {
            continue;
        }
        let projected = events
            .iter()
            .map(|event| {
                let envelope = serde_json::to_value(event).map_err(|error| error.to_string())?;
                let operation =
                    super::super::event_log::projection_operation_from_envelope(&envelope)
                        .ok_or_else(|| "committed command has no domain projection".to_owned())?;
                // Rebuild the exact writes accepted at admission through the
                // ProjectionState projector. Capability grants derive their
                // immutable authority depth/root audit from the confirmed
                // parent-grant state; the schema-only projector has no
                // authority resolver and therefore rejects every grant here.
                // The accepted-event lane also preserves the frozen invite
                // lifecycle binding already checked before durable admission.
                let writes = confirmed_event_cell_writes(state, event)?;
                Ok((operation, writes))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let contextual = projected
            .iter()
            .map(|(operation, _)| match &operation.event_kind {
                arkret_wire::EventKind::MemberState => {
                    accepted_member_state_reducer_operation(operation)
                }
                arkret_wire::EventKind::CircleMemberState => {
                    accepted_circle_member_reducer_operation(operation)
                }
                _ => operation.clone(),
            })
            .collect::<Vec<_>>();
        let staged = contextual
            .iter()
            .zip(&projected)
            .map(|(operation, (_, writes))| (operation, writes.as_slice()))
            .collect::<Vec<_>>();
        let effects = state
            .projections()
            .apply_operations_with_effects_atomic(&staged, state.hlc())?;
        publish_confirmed_command_unit(state, &projected, &effects).await?;
    }
    Ok(())
}

/// This phase does not reapply reducers. A failed mirror prevents every timeline
/// write for the unit, but the caller still owns reducer crash recovery.
async fn publish_confirmed_command_unit(
    state: &AppState,
    projected: &[(Operation, Vec<arkret_wire::cbs::ProjectedCellWrite>)],
    effects: &[ProjectionEffectView],
) -> Result<(), String> {
    if projected.len() != effects.len() {
        return Err("confirmed unit has an incomplete effect list".to_owned());
    }
    for ((operation, _), effect) in projected.iter().zip(effects) {
        project_accepted_operations_inner(
            state,
            operation.context.sender.signing_principal_id().as_str(),
            "",
            std::slice::from_ref(operation),
            None,
            Some(effect),
        )
        .await?;
    }
    // The durable timeline is downstream of every member's mirror work.
    // Its existing event-id key suppresses duplicate publication on retry;
    // it is not a checkpoint for replaying the in-memory reducer.
    for (operation, _) in projected {
        let origin = operation.context.sender.signing_principal_id();
        let outcome = persist_and_publish_projection_event(
            state,
            projection_event_from_operation(operation, Some(origin.as_str())),
        )
        .await
        .map_err(|error| format!("publish confirmed command timeline: {error}"))?;
        if outcome == soland_services::events::ProjectedEventAppendResult::Inserted {
            match kinds::canonical_kind(operation) {
                arkret_wire::EventKind::MessageCreate => {
                    crate::routing::events::notify::dispatch_message_notifications(state, operation)
                        .await
                }
                arkret_wire::EventKind::RelationCreate => {
                    crate::routing::events::notify::dispatch_assignment_notifications(
                        state, operation,
                    )
                    .await
                }
                arkret_wire::EventKind::StrandUpdate => {
                    crate::routing::events::notify::dispatch_schedule_notifications(
                        state, operation,
                    )
                    .await
                }
                _ => {}
            }
        }
    }
    Ok(())
}
