use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_models_collaboration::events_payloads::RealmKeyShareTarget;
use arkret_models_collaboration::sync_frames::account_sync::{
    MlsWelcomeProjectedDeviceMessage, MlsWelcomeProjectionBinding,
    RealmKeyShareProjectedDeviceMessage,
};
use serde::Serialize;
use serde_json::{Value, json};
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
    project_accepted_operations_inner(state, origin, source_device_id, operations, None).await;
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
    cell_writes: &[arkret_wire::cba::ProjectedCellWrite],
) {
    project_accepted_operations_inner(
        state,
        origin,
        source_device_id,
        std::slice::from_ref(operation),
        Some(cell_writes),
    )
    .await;
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
) -> Vec<arkret_wire::cba::ProjectedCellWrite> {
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

fn accepted_circle_member_reducer_operation(operation: &Operation) -> Operation {
    let mut contextual = operation.clone();
    if let Some(payload) = contextual.payload.as_object_mut() {
        payload.insert("manage_capability_verified".to_owned(), Value::Bool(true));
    }
    contextual
}

/// Keep receiver time as reducer context without contaminating the closed
/// producer payload consumed by the typed membership gate.
fn accepted_member_state_reducer_operation(operation: &Operation) -> Operation {
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
) {
    let ProjectionEffectView::Mls(effect) = effect else {
        return;
    };

    match effect {
        MlsProjectionEffect::KeyPackagePublished { keypackage_id } => {
            let record = state.projections().mls_key_package_record(keypackage_id);
            if let Some(record) = record
                && let Err(error) = state.mls_key_packages().store_key_package(&record).await
            {
                tracing::warn!(%error, keypackage_id = %keypackage_id, "failed to mirror MLS KeyPackage publish");
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
                    claimed_at: *claimed_at,
                    claim_expires_at_unix_ms: operation
                        .payload
                        .get("claim_expires_at_unix_ms")
                        .and_then(Value::as_i64),
                })
                .await
            {
                tracing::warn!(%error, keypackage_id = %keypackage_id, "failed to mirror MLS KeyPackage claim");
            }
        }
        MlsProjectionEffect::WelcomeEnqueued {
            welcome_id,
            recipient_actor_id,
            recipient_device_id,
            ..
        } => {
            let record = state.projections().mls_welcome_record(
                recipient_actor_id,
                recipient_device_id,
                welcome_id,
            );
            if let Some(record) = record {
                if let Err(error) = state
                    .mls_key_packages()
                    .enqueue_welcome(record.clone())
                    .await
                {
                    tracing::warn!(%error, welcome_id = %welcome_id, "failed to mirror MLS Welcome enqueue");
                }
                project_mls_welcome_to_device(
                    state,
                    origin,
                    source_device_id,
                    operation,
                    &record,
                    welcome_id,
                )
                .await;
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
            let binding = operation
                .payload
                .get("governance_binding")
                .or_else(|| operation.payload.get("mls_governance_binding"))
                .cloned()
                .unwrap_or(Value::Null);
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
                tracing::warn!(%error, group_id = %group_id, "failed to mirror MLS genesis epoch");
            }
            bind_circle_mls_group(state, group_id, effective_scope, false);
        }
        MlsProjectionEffect::CommitEpochAdvanced {
            group_id,
            effective_scope,
            previous_epoch,
            leader_actor_id,
            ..
        } => {
            let binding = operation
                .payload
                .get("governance_binding")
                .or_else(|| operation.payload.get("mls_governance_binding"))
                .cloned()
                .unwrap_or(Value::Null);
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
                tracing::warn!(%error, group_id = %group_id, "failed to mirror MLS commit epoch");
            }
            bind_circle_mls_group(state, group_id, effective_scope, true);
        }
        MlsProjectionEffect::CommitFrontierContested {
            group_id,
            effective_scope,
            epoch,
        } => {
            // §2.5.2 — concurrent commits drove `covered_frontier_cell` to `⊥`.
            // Mirror the contested marker onto the durable epoch row so the
            // group stays fail-closed (`decryption_pending`) across restarts
            // until a resolving commit advances the epoch.
            if let Err(error) = state
                .mls_commits()
                .mark_frontier_contested(effective_scope, group_id, *epoch)
                .await
            {
                tracing::warn!(%error, group_id = %group_id, "failed to mirror MLS contested frontier");
            }
        }
    }
}

fn bind_circle_mls_group(
    state: &AppState,
    group_id: &str,
    effective_scope: &Value,
    clear_pending_removals: bool,
) {
    state
        .projections()
        .bind_circle_mls_group(group_id, effective_scope, clear_pending_removals);
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
async fn write_through_projection(state: &AppState, operation: &Operation) {
    use soland_services::projection::ProjectionWriteThroughRecord;

    let Some(snapshot) = state
        .projections()
        .projection_write_through_record(operation)
    else {
        return;
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
    if let Err(error) = result {
        tracing::warn!(
            %error,
            operation_id = %operation.operation_id,
            "projection write-through to persistence failed; in-memory state stays authoritative"
        );
    }
}

pub async fn project_accepted_operations(state: &AppState, origin: &str, operations: &[Operation]) {
    project_accepted_operations_inner(state, origin, "", operations, None).await;
}

pub async fn mirror_join_authorisation_consumption(
    state: &AppState,
    origin: &str,
    operation: &Operation,
) {
    if kinds::canonical_kind_for_operation(operation) != Some(arkret_wire::EventKind::InviteCreate)
    {
        return;
    }
    let mut refs = operation
        .refs
        .iter()
        .filter(|reference| reference.role == "join_authorised_by")
        .filter_map(|reference| {
            let value = reference.id.trim();
            (!value.is_empty()).then(|| value.to_owned())
        })
        .collect::<Vec<_>>();
    if refs.is_empty() {
        refs = operation
            .payload
            .get("refs")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter(|reference| {
                reference.get("role").and_then(serde_json::Value::as_str)
                    == Some("join_authorised_by")
            })
            .filter_map(|reference| {
                reference
                    .get("id")
                    .or_else(|| reference.get("digest"))
                    .and_then(serde_json::Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                    .map(ToOwned::to_owned)
            })
            .collect();
    }
    if refs.is_empty() {
        return;
    }
    match state
        .join_applications()
        .consume_review_authorisations(
            operation.realm_id.as_str(),
            &refs,
            origin,
            operation.created_at,
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => tracing::error!(
            operation_id = %operation.operation_id,
            "accepted invite could not consume its private join authorization"
        ),
        Err(error) => tracing::error!(
            operation_id = %operation.operation_id,
            %error,
            "failed to persist private join-authorization consumption"
        ),
    }
}

async fn project_accepted_operations_inner(
    state: &AppState,
    origin: &str,
    source_device_id: &str,
    operations: &[Operation],
    canonical_cell_writes: Option<&[arkret_wire::cba::ProjectedCellWrite]>,
) {
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
            crate::routing::events::notify::dispatch_message_notifications(state, operation).await;
        } else if kinds::operation_is_invite_create(operation) {
            project_invite_create_operation(state, origin, operation).await;
        } else if kinds::operation_is_invite_third_party(operation) {
            project_invite_third_party_operation(state, operation).await;
        } else if kinds::operation_is_invite_claim(operation) {
            project_invite_claim_operation(state, operation).await;
        } else if kinds::canonical_kind(operation) == arkret_wire::EventKind::InviteAccept {
            project_invite_accept_operation(state, origin, operation).await;
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
            project_member_identity_update(state, operation);
        }
        // Cache ak.realm.read_receipt_policy state into ProjectionState so the
        // parent/child policy-combination validators hit a BTreeMap lookup
        // instead of scanning the durable Event store.
        // (R1.2 renamed `ak.space.read_receipt_policy` to `ak.realm.*`.)
        //
        // NOT a Signal fanout filter: `disclosure="disabled"` and
        // `visibility="private"` are enforced client-side
        // (`discovery/read-receipts.md` §2.5). `ak.receipt.read` travels as
        // Signal plaintext inside the ciphertext, so this service cannot read
        // it and MUST NOT route or drop an envelope by receipt content.
        if kinds::canonical_kind(operation) == arkret_wire::EventKind::RealmReadReceiptPolicy {
            project_read_receipt_policy(state, operation);
        }
        if kinds::canonical_kind(operation) == arkret_wire::EventKind::AccountDataSet {
            project_account_data_set(state, origin, source_device_id, operation).await;
        }
        if kinds::canonical_kind(operation) == arkret_wire::EventKind::SelfModerationReport {
            materialize_moderation_report(state, operation).await;
        }
        crate::routing::identity::consent::project_consent_operation(state, operation).await;
        // Device-identity Phase 1 — persist an accepted `ak.device.authorize`'s
        // `payload.device_public_key` into the devices table so the
        // `keys/query` signing-key directory resolves devices that were
        // authorized but never opened a session (previously the key only
        // landed via the session-grant exchange path).
        if kinds::canonical_kind(operation) == arkret_wire::EventKind::DeviceAuthorize {
            project_device_authorize(state, operation).await;
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
        let reducer_effect =
            if actor_private_read_cursor_matches_origin(origin, source_device_id, operation) {
                let cell_writes = canonical_cell_writes
                    .map(ToOwned::to_owned)
                    .unwrap_or_else(|| accepted_operation_cell_writes(state, origin, operation));
                if kinds::canonical_kind(operation) == arkret_wire::EventKind::ReadCursorAdvance {
                    Some(state.projections().apply_read_cursor(reducer_operation))
                } else {
                    Some(state.projections().apply_via_lattice_registry(
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
            // Durable member-device history shares are themselves the delivery
            // source of truth. Enqueue from the accepted canonical kind instead
            // of coupling transport delivery to the reducer's transient effect
            // view: replay/hydration may legitimately collapse that view after
            // the cell write, while the idempotent device-message projection
            // must still be rebuilt.
            if kinds::canonical_kind(operation) == arkret_wire::EventKind::RealmKeyShare {
                project_realm_key_share_to_device(state, origin, source_device_id, operation).await;
            }
            fanout_projection_effect_private_update(state, origin, source_device_id, &effect).await;
            mirror_mls_effect_to_persistence(state, origin, source_device_id, operation, &effect)
                .await;
            mirror_moderation_effect_to_persistence(state, operation, &effect).await;
            // SOL-ORG-04 — persist an accepted `ak.realm.organization`
            // relationship statement projection durably.
            mirror_realm_organization_effect_to_persistence(state, &effect).await;
            // P1 — fold the projected capability grant cell back into the
            // SolandAuthzEngine read index. The cell is the source of truth;
            // the engine map is a read-side index maintained by projection
            // (no longer written directly by HTTP handlers).
            refresh_authz_index_from_capability_effect(state, &effect);
        }
        mirror_join_authorisation_consumption(state, origin, operation).await;
        // Write through Space-container/Strand/Morph projection changes to durable
        // persistence. Captures the in-memory projection snapshot
        // (under lock), then upserts to persistence after releasing the
        // lock so any backend latency doesn't block other reducer paths.
        // Mirrors the canonical wire kinds the reducer dispatches into
        // `ProjectionState::{space_containers,strands,morphs}`.
        write_through_projection(state, operation).await;
        crate::routing::identity::account::project_canonical_direct_binding(state, operation).await;
        if kinds::canonical_kind(operation) == arkret_wire::EventKind::RelationCreate {
            crate::routing::events::notify::dispatch_assignment_notifications(state, operation)
                .await;
        }
        if kinds::canonical_kind(operation) == arkret_wire::EventKind::StrandUpdate {
            crate::routing::events::notify::dispatch_schedule_notifications(state, operation).await;
        }
        // AKP-0016 — mirror agent_participation ceiling changes into the
        // agent_participation_ceiling projection table (read by
        // participation.set / .get ceiling resolution).
        if let Some(record) =
            crate::routing::events::operations::agent_participation_ceiling_record(operation)
            && let Err(error) = state.agent_participations().store_ceiling(record).await
        {
            tracing::warn!(%error, "failed to persist agent participation ceiling");
        }
        if canonical_cell_writes.is_none() {
            let projected = projection_event_from_operation(operation, Some(origin));
            // Operation-only lanes have no canonical Event acceptance
            // transaction, so they still own projection timeline persistence.
            if let Err(error) = persist_and_publish_projection_event(state, projected).await {
                tracing::warn!(%error, "failed to persist projection event before publish");
            }
        }
        if let Err(error) = persist_projected_operation(state, origin, operation).await {
            tracing::warn!(
                error = %error,
                operation_id = %operation.operation_id,
                event_kind = %operation.event_kind,
                "failed to persist accepted operation projection"
            );
        }
    }
}

async fn materialize_moderation_report(state: &AppState, operation: &Operation) {
    let event_id = &operation.context.event_id;
    let report_id = arkret_identifiers::ReportId::from_event_id(event_id);
    let queue_item_id = arkret_identifiers::ModerationQueueItemId::from_event_id(event_id);
    let Some(mut report) = operation.payload.as_object().cloned() else {
        tracing::error!(event_id = %event_id, "accepted moderation report payload is not an object");
        return;
    };
    report.insert("report_id".to_owned(), serde_json::json!(report_id));
    report.insert("event_id".to_owned(), serde_json::json!(event_id));
    report.insert(
        "effective_scope".to_owned(),
        serde_json::json!(operation.context.accepted_scope_ref),
    );
    if operation
        .payload
        .get("target_ref")
        .and_then(Value::as_str)
        .is_some_and(|target| target.starts_with("ak:event:"))
    {
        report.insert(
            "target_event_id".to_owned(),
            operation.payload["target_ref"].clone(),
        );
    }
    report.insert(
        "created_at".to_owned(),
        serde_json::json!(operation.created_at),
    );
    let report = Value::Object(report);
    if let Err(error) = state
        .governance()
        .append_moderation_report(report.clone())
        .await
    {
        tracing::error!(%error, event_id = %event_id, "accepted moderation report projection failed");
    }
    let queue_item = serde_json::json!({
        "id": queue_item_id,
        "report": report,
        "status": "submitted",
        "priority": "normal",
        "visibility": "metadata_only",
        "assigned_to": [format!("{}#moderation", state.service_id())],
        "audit_refs": [],
        "created_at": operation.created_at,
    });
    if let Err(error) = state
        .governance()
        .upsert_moderation_queue_item(queue_item)
        .await
    {
        tracing::error!(%error, event_id = %event_id, "accepted moderation queue projection failed");
    }
}

pub(crate) async fn mirror_moderation_effect_to_persistence(
    state: &AppState,
    operation: &Operation,
    effect: &ProjectionEffectView,
) {
    let ProjectionEffectView::ModerationAppealProjected {
        appeal_id,
        new_state,
        ..
    } = effect
    else {
        return;
    };

    #[derive(Serialize)]
    struct ProjectedAppealRecord<T> {
        #[serde(flatten)]
        payload: T,
        #[serde(rename = "appeal_id", skip_serializing_if = "Option::is_none")]
        derived_appeal_id: Option<String>,
        event_kind: arkret_wire::EventKind,
        appeal_state: String,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        projected_at: chrono::DateTime<chrono::Utc>,
    }

    fn record<T: Serialize>(
        payload: T,
        derived_appeal_id: Option<String>,
        operation: &Operation,
        appeal_state: &str,
    ) -> Value {
        serde_json::to_value(ProjectedAppealRecord {
            payload,
            derived_appeal_id,
            event_kind: operation.event_kind.clone(),
            appeal_state: appeal_state.to_owned(),
            projected_at: operation.created_at.to_owned(),
        })
        .expect("typed moderation appeal projection record serializes")
    }

    let record = match &operation.event_kind {
        arkret_wire::EventKind::ModerationAppealSubmit => operation
            .typed_payload::<arkret_wire::event_spec::ModerationAppealSubmit>()
            .map(|payload| record(payload, Some(appeal_id.clone()), operation, new_state)),
        arkret_wire::EventKind::ModerationAppealReview => operation
            .typed_payload::<arkret_wire::event_spec::ModerationAppealReview>()
            .map(|payload| record(payload, None, operation, new_state)),
        arkret_wire::EventKind::ModerationAppealDecision => operation
            .typed_payload::<arkret_wire::event_spec::ModerationAppealDecision>()
            .map(|payload| record(payload, None, operation, new_state)),
        arkret_wire::EventKind::ModerationAppealClose => operation
            .typed_payload::<arkret_wire::event_spec::ModerationAppealClose>()
            .map(|payload| record(payload, None, operation, new_state)),
        _ => return,
    };
    let Ok(record) = record else {
        tracing::warn!(
            operation_id = %operation.operation_id,
            event_kind = %operation.event_kind,
            "typed moderation appeal payload rejected before persistence"
        );
        return;
    };
    if let Err(error) = state.governance().append_moderation_appeal(record).await {
        tracing::warn!(
            %error,
            appeal_id = %appeal_id,
            operation_id = %operation.operation_id,
            "failed to mirror moderation appeal event"
        );
    }
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
) {
    let ProjectionEffectView::RealmOrganizationProjected {
        realm_id,
        organization_id,
        relationship,
        ..
    } = effect
    else {
        return;
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
    let Some(row) = row else {
        return;
    };
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
        realm_frontier_digest: row.realm_frontier_digest,
        proof_digest: row.proof_digest,
        delegation_ref: row.delegation_ref,
        issuer_role: row.issuer_role,
        updated_at: row.updated_at,
    };
    if let Err(error) = state
        .event_queries()
        .store_realm_organization_statement(&record)
        .await
    {
        tracing::warn!(
            %error,
            realm_id = %record.realm_id,
            organization_id = %record.organization_id,
            relationship = %record.relationship,
            "failed to persist ak.realm.organization relationship statement"
        );
    }
}

async fn project_mls_welcome_to_device(
    state: &AppState,
    origin: &str,
    source_device_id: &str,
    operation: &Operation,
    record: &MlsWelcomeState,
    welcome_id: &str,
) {
    let Ok(welcome) = operation.typed_payload::<arkret_wire::event_spec::MlsWelcome>() else {
        tracing::warn!(%welcome_id, operation_id = %operation.operation_id, "accepted MLS Welcome payload is not the typed wire shape");
        return;
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
        tracing::warn!(
            %welcome_id,
            operation_id = %operation.operation_id,
            "cannot enqueue MLS Welcome device message without sender device id"
        );
        return;
    }

    let content = match serde_json::to_value(MlsWelcomeProjectedDeviceMessage {
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
            tracing::warn!(%error, %welcome_id, "failed to serialize typed MLS Welcome device message");
            return;
        }
    };
    let message = DeviceMessageState {
        idempotency_key: format!("mls_welcome:{welcome_id}"),
        sender: origin.to_owned(),
        recipient: record.recipient_actor_id.clone(),
        device_id: record.recipient_device_id.clone(),
        position: state.next_to_device_position(),
        content,
        created_at: operation.created_at,
    };
    if let Err(error) = state.deliveries().append_device_message(message).await {
        tracing::warn!(
            %error,
            %welcome_id,
            operation_id = %operation.operation_id,
            "failed to enqueue MLS Welcome to-device message"
        );
    }
}

async fn project_realm_key_share_to_device(
    state: &AppState,
    origin: &str,
    source_device_id: &str,
    operation: &Operation,
) {
    let Ok(share) = operation.typed_payload::<arkret_wire::event_spec::RealmKeyShare>() else {
        return;
    };
    if share.key_scope.effective_scope.realm_id().as_str() != operation.realm_id.as_str()
        || share
            .key_scope
            .from_epoch
            .zip(share.key_scope.to_epoch)
            .is_some_and(|(from_epoch, to_epoch)| from_epoch > to_epoch)
    {
        tracing::warn!(
            operation_id = %operation.operation_id,
            "accepted realm key share failed delivery projection invariants"
        );
        return;
    }
    // share_kind=realm_recovery_key (recipient_device_id absent): the recipient is
    // an offline recovery org delivered via the durable Event, not a to-device
    // queue (encryption-and-audit.md §2.10.8). No device message is enqueued.
    let RealmKeyShareTarget::MemberDevice {
        recipient_device_id,
    } = &share.target
    else {
        return;
    };
    let recipient_device_id = recipient_device_id.to_string();
    let recipient = share.recipient_principal_id.to_string();
    let sender_device_id = if source_device_id.trim().is_empty() {
        share.sender_device_id.as_str()
    } else {
        source_device_id.trim()
    }
    .to_owned();
    if sender_device_id.is_empty() {
        tracing::warn!(
            operation_id = %operation.operation_id,
            "cannot enqueue realm key share device message without sender device id"
        );
        return;
    }
    let content = match serde_json::to_value(RealmKeyShareProjectedDeviceMessage {
        sender_device_id,
        realm_id: operation.realm_id.clone(),
        operation_id: operation.operation_id.to_string(),
        payload: share,
    }) {
        Ok(content) => content,
        Err(error) => {
            tracing::warn!(%error, operation_id = %operation.operation_id, "failed to serialize typed Realm Key Share device message");
            return;
        }
    };
    let record = DeviceMessageState {
        idempotency_key: format!("realm_key_share:{}", operation.operation_id),
        sender: origin.to_owned(),
        recipient,
        device_id: recipient_device_id,
        position: state.next_to_device_position(),
        content,
        created_at: operation.created_at,
    };
    if let Err(error) = state.deliveries().append_device_message(record).await {
        tracing::warn!(
            %error,
            operation_id = %operation.operation_id,
            "failed to enqueue realm key share to-device message"
        );
    }
}

/// Device-identity Phase 1 — persist an accepted `ak.device.authorize`'s
/// authoritative `device_public_key` into the devices inventory so the
/// `keys/query` signing-key directory (`device-lifecycle.md` §8.2) can resolve
/// a device that was authorized but never opened a session. Idempotent and
/// non-destructive: an existing row keeps its `created_at`, `display_name`,
/// revocation, any already-recorded `device_public_key`, and an atomically
/// projected generation binding; a verified state is never downgraded. The
/// device possession proof was already verified at ingest.
async fn project_device_authorize(state: &crate::state::AppState, operation: &Operation) {
    use soland_services::identity::{DeviceIdentity, FindDeviceQuery, SaveDeviceCommand};
    let typed = match operation.typed_payload::<arkret_wire::event_spec::DeviceAuthorize>() {
        Ok(typed) => typed,
        Err(error) => {
            tracing::warn!(%error, "accepted ak.device.authorize payload is not the typed wire shape; skipping projection");
            return;
        }
    };
    let principal_id = typed.principal_id.as_str();
    let device_id = typed.device_id.as_str();
    let device_public_key = typed.device_public_key.trim();
    if device_public_key.is_empty() {
        // No key to project; nothing the directory needs from this event.
        return;
    }
    let existing = state
        .identities()
        .find_device(FindDeviceQuery {
            actor_id: principal_id.to_owned(),
            device_id: device_id.to_owned(),
        })
        .await
        .ok()
        .flatten();
    let updated_at = now();
    let created_at = existing
        .as_ref()
        .map(|device| device.created_at)
        .unwrap_or(updated_at);
    let display_name = existing
        .as_ref()
        .and_then(|device| device.display_name.clone());
    // An accepted device.authorize confirms the device; never downgrade an
    // already-verified row, and treat a fresh authorize as verified.
    let verification_state = "verified".to_owned();
    let revoked_at = existing.as_ref().and_then(|device| device.revoked_at);
    // The accepted Event's own id, not the Operation id retyped into one. An
    // `ak:operation:` id is producer-allocated and an `ak:event:` id is derived
    // from Event content, so retyping across those two id forms produces a
    // value no Event can ever have: the `canonical_event` lookup below always
    // missed, and `GET /_arkret/self/account/viewer` answered 500 parsing the
    // stored result back as an `EventId`.
    let authorize_event_id = super::event_json::operation_event_id(operation);
    if !authorize_event_id.starts_with("ak:event:") {
        tracing::error!(
            operation_id = %operation.operation_id,
            "accepted device.authorize carries no Event id; device authorization is not projected"
        );
        return;
    }
    let authorized_generation_ref = match state
        .event_queries()
        .canonical_event(&authorize_event_id)
        .await
    {
        Ok(Some(record)) => {
            crate::routing::identity::device_generation::authorized_generation_for_event(
                state, &record,
            )
            .await
            .ok()
            .flatten()
        }
        _ => None,
    };
    let mut device_payload = existing
        .as_ref()
        .map(|device| device.payload.clone())
        .unwrap_or_else(|| json!({ "device_id": device_id }));
    if !device_payload.is_object() {
        device_payload = json!({ "device_id": device_id });
    }
    if let Some(map) = device_payload.as_object_mut() {
        map.insert(
            "device_public_key".to_owned(),
            Value::String(device_public_key.to_owned()),
        );
        map.entry("device_id".to_owned())
            .or_insert_with(|| Value::String(device_id.to_owned()));
        // §5.2: hpke_key and canonical algorithms are part of the authorized
        // device record; project them verbatim (services MUST NOT substitute
        // these values in projection).
        if !typed.hpke_key.trim().is_empty() {
            map.insert(
                "hpke_key".to_owned(),
                Value::String(typed.hpke_key.to_string()),
            );
        }
        map.insert(
            "algorithms".to_owned(),
            Value::Array(
                typed
                    .algorithms
                    .iter()
                    .map(|algorithm| Value::String(algorithm.to_string()))
                    .collect(),
            ),
        );
        map.insert("device_authorize_projected".to_owned(), Value::Bool(true));
        map.insert(
            "device_authorize_event_id".to_owned(),
            Value::String(authorize_event_id),
        );
        if let Some(generation_ref) = authorized_generation_ref {
            map.insert(
                "authorized_generation_ref".to_owned(),
                Value::String(generation_ref),
            );
        }
        if let Some(binding_kind) = operation.payload.get("authorization_binding_kind") {
            map.insert(
                "authorization_binding_kind".to_owned(),
                binding_kind.clone(),
            );
        }
        if let Some(authorized_by) = operation.payload.get("authorized_by") {
            map.insert("authorized_by".to_owned(), authorized_by.clone());
        }
    }
    let device = DeviceIdentity {
        actor_id: principal_id.to_owned(),
        device_id: device_id.to_owned(),
        display_name,
        verification_state,
        payload: device_payload,
        created_at,
        updated_at,
        revoked_at,
    };
    if let Err(error) = state
        .identities()
        .save_device(SaveDeviceCommand {
            actor_id: principal_id.to_owned(),
            device_id: device_id.to_owned(),
            display_name: device.display_name.clone(),
            device,
        })
        .await
    {
        tracing::warn!(%error, "failed to project ak.device.authorize device_public_key");
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::identity::device_messages::device_message_envelopes_after;

    fn accepted_test_operation(
        operation_id: arkret_identifiers::OperationId,
        realm_id: arkret_identifiers::RealmId,
        actor: &str,
        actor_seq: u64,
        kind: arkret_wire::EventKind,
        payload: serde_json::Value,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> arkret_event_draft::ProjectedEventOperation {
        let event = arkret_wire::test_support::raw_event_at(
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
        )
        .unwrap()
    }

    #[tokio::test]
    async fn canonical_no_hlc_projection_does_not_restate_or_append_synthetic_timeline() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let actor = arkret_identifiers::DidFullId::new("did:web:alice.example".to_owned()).unwrap();
        let actor_core = arkret_wire::project_full_id_to_core_id(&actor).unwrap();
        let realm_id = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x32; 32],
        ));
        let created_at = chrono::DateTime::parse_from_rfc3339("2026-08-09T02:00:00.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let mut event = arkret_wire::test_support::raw_event_at(
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
        event.event_id = event.derive_event_id().unwrap();
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

    #[tokio::test]
    async fn realm_key_share_device_projection_accepts_projected_payload_context() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let realm_id = arkret_identifiers::RealmId::new(
            "ak:realm:AfQwJHPhBleRZGcIQe5JusJEaZwwkeT8TDwxd957Ic4z".to_owned(),
        )
        .unwrap();
        let operation_id = arkret_identifiers::OperationId::new(
            "ak:operation:0196419b-1000-7000-8000-000000000102",
        )
        .unwrap();
        let sender = "ak:did_core:web:alice.example";
        let sender_device = "ak:device:01904100-0000-7000-8000-a11ce0000101";
        let recipient = "ak:did_core:web:bob.example";
        let recipient_device = "ak:device:01904100-0000-7000-8000-b0b000000101";
        let payload = json!({
            "share_kind": "member_device",
            "recipient_principal_id": recipient,
            "recipient_device_id": recipient_device,
            "sender_device_id": sender_device,
            "source_authorization_ref": "ak:event:AauJX1Coqu2PGQIViJss03KgbYKe__UV68K84NDE8zt6",
            "sender_device_signature": {
                "signature_algorithm": "Ed25519",
                "signature": "signature",
                "signer_public_key_multibase": "z6MkkWfGNkv1TUe64XN2p4WMVabjTxzk4snewMn4774HxGyB"
            },
            "key_scope": {
                "effective_scope": {"kind": "realm", "realm_id": realm_id.as_str()},
                "policy_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "from_epoch": 0,
                "to_epoch": 0
            },
            "ciphertext": "sealed",
            "created_at": "2026-07-05T00:00:00.000Z"
        });
        let operation = accepted_test_operation(
            operation_id.clone(),
            realm_id.clone(),
            sender,
            1,
            arkret_wire::EventKind::RealmKeyShare,
            payload,
            chrono::Utc::now(),
        );

        project_accepted_operations_from_device(
            &state,
            sender,
            sender_device,
            std::slice::from_ref(&operation),
        )
        .await;

        let queued = state
            .deliveries()
            .device_messages_after(recipient, recipient_device, 0)
            .await
            .expect("queued device messages");
        assert_eq!(queued.len(), 1);
        assert_eq!(
            queued[0].content["kind"],
            arkret_wire::EventKind::RealmKeyShare.as_str()
        );
        assert_eq!(
            queued[0].content["content"]["payload"]["ciphertext"],
            "sealed"
        );
    }

    #[test]
    fn realm_key_share_device_projection_preserves_payload_in_envelope_content() {
        let realm_id = "ak:realm:ARZTx1K62JEESOCDcEVZTToJPN3vCoG0zRRnpm3t3OeX";
        let operation_id = "ak:operation:0196419b-1000-7000-8000-000000000002";
        let sender = "ak:did_core:web:alice.example";
        let sender_device = "ak:device:01904100-0000-7000-8000-a11ce0000001";
        let recipient = "ak:did_core:web:bob.example";
        let recipient_device = "ak:device:01904100-0000-7000-8000-b0b000000001";
        let payload = json!({
            "share_kind": "member_device",
            "recipient_principal_id": recipient,
            "recipient_device_id": recipient_device,
            "sender_device_id": sender_device,
            "source_authorization_ref": "ak:event:AYqEzQ3jW02EHkMjxFQTlyeowxPQXJE4fI6JGOnzi23t",
            "sender_device_signature": {
                "signature_algorithm": "Ed25519",
                "kid": "did:web:alice.example#ak:device:01904100-0000-7000-8000-a11ce0000001",
                "sig": "signature"
            },
            "key_scope": {
                "effective_scope": {"kind": "realm", "realm_id": realm_id},
                "policy_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "from_epoch": 0,
                "to_epoch": 0
            },
            "ciphertext": "sealed",
            "aad_digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
            "created_at": "2026-06-30T00:00:00.000Z"
        });
        let created_at = chrono::Utc::now();
        // Production assigns the `message_id` in the storage `append`
        // (the persistence adapter assigns a message id); this test builds the
        // record by hand, so inject it the same way the store would.
        let projected = RealmKeyShareProjectedDeviceMessage {
            sender_device_id: sender_device.to_owned(),
            realm_id: arkret_identifiers::RealmId::new(realm_id.to_owned()).unwrap(),
            operation_id: operation_id.to_owned(),
            payload: serde_json::from_value(payload.clone()).unwrap(),
        };
        let mut content = serde_json::to_value(projected).unwrap();
        content.as_object_mut().unwrap().insert(
            "message_id".to_owned(),
            json!("ak:device_message:0196419b-1000-7000-8000-000000000099"),
        );
        let record = DeviceMessageState {
            idempotency_key: format!("realm_key_share:{operation_id}"),
            sender: sender.to_owned(),
            recipient: recipient.to_owned(),
            device_id: recipient_device.to_owned(),
            position: 1,
            content,
            created_at,
        };

        let delivered = device_message_envelopes_after(&[record]);
        assert_eq!(delivered.len(), 1);
        assert_eq!(
            delivered[0].kind.as_str(),
            arkret_wire::EventKind::RealmKeyShare.as_str()
        );
        assert_eq!(delivered[0].content["realm_id"], realm_id);
        assert_eq!(delivered[0].content["operation_id"], operation_id);
        assert_eq!(delivered[0].content["payload"], payload);
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
                "actor_id": "ak:did_core:web:agent.example",
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
                "actor_id": "ak:did_core:web:member.example",
                "membership": "join",
                "delivery_status": "unroutable"
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
}
