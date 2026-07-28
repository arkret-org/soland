use arkret_event_draft::Operation;
use arkret_models_collaboration::events_payloads::RealmKeyShareTarget;
use serde_json::{Value, json};
use soland_services::delivery::DeviceMessageState;
use soland_services::events::MlsWelcomeState;
use soland_services::operation_semantics as kinds;
use soland_services::projection::{MlsProjectionEffect, ProjectionEffectView};

use super::*;
use crate::ids;
use crate::state::AppState;

pub async fn project_accepted_operations_from_device(
    state: &AppState,
    origin: &str,
    source_device_id: &str,
    operations: &[Operation],
) {
    project_accepted_operations_inner(state, origin, source_device_id, operations, None).await;
}

/// The registry-derived cell writes for an accepted Operation.
///
/// `event-and-patch.md` §2.4.2 makes the registered reducer contract the only
/// source of a cell write; v1 deleted the producer `effects[]` this lane used
/// to replay. The lane carries Operations rather than signed Events — the
/// service-authored admin/circle/realm projections never had one — so the
/// Operation is restated in the shape the single evaluator reads: `kind`,
/// `event_id`, `actor_id` and the wire payload with the projection-context
/// fields this crate injected stripped back out. Nothing here decides what an
/// Event writes; the registry still does.
///
/// An unprojectable Operation yields no writes, which is fail-closed: the
/// reducer rejects a kind whose contract declares writes when handed none.
fn accepted_operation_cell_writes(
    state: &AppState,
    origin: &str,
    operation: &Operation,
) -> Vec<arkret_wire::cba::ProjectedCellWrite> {
    let Some(kind) = kinds::canonical_kind_for_operation(operation) else {
        return Vec::new();
    };
    if !arkret_wire::events::EventKind::from(kind)
        .descriptor()
        .is_some_and(|descriptor| descriptor.reducer_input)
    {
        return Vec::new();
    }
    let event_id = super::event_json::operation_event_id(operation);
    let event_id = if event_id.starts_with("ak:event:") {
        event_id
    } else {
        match event_id.strip_prefix("ak:operation:") {
            Some(suffix) => format!("ak:event:{suffix}"),
            None => return Vec::new(),
        }
    };
    let actor_id = operation
        .payload
        .get("sender")
        .and_then(Value::as_str)
        .unwrap_or(origin);
    let realm_id = operation.realm_id.as_str();
    let envelope = json!({
        "event_id": event_id,
        "kind": kind,
        "realm_id": realm_id,
        "scope_ref": { "kind": "realm", "realm_id": realm_id },
        "actor_id": actor_id,
        "actor_seq": 0,
        "created_at": arkret_canonical::format_timestamp_canonical(operation.created_at),
        "prev_refs": [],
        "payload": crate::routing::events::projection_context_stripped_payload(&operation.payload),
        "proofs": [],
    });
    let event = match serde_json::from_value::<arkret_wire::Event>(envelope) {
        Ok(event) => event,
        Err(error) => {
            tracing::error!(
                operation_id = %operation.operation_id,
                %kind,
                %error,
                "accepted operation cannot be restated as an Event envelope; \
                 the reducer will see no derived cell write"
            );
            return Vec::new();
        }
    };
    match state.projections().project_cell_writes(&event) {
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

fn accepted_circle_member_reducer_operation(
    operation: &Operation,
    trusted_sidecar_controller: Option<&str>,
) -> Operation {
    let mut contextual = operation.clone();
    if let Some(payload) = contextual.payload.as_object_mut() {
        if let Some(controller) = trusted_sidecar_controller {
            payload.insert("sender".to_owned(), Value::String(controller.to_owned()));
        }
        payload.insert("manage_capability_verified".to_owned(), Value::Bool(true));
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
                    ssk_generation: None,
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
            covered_seals,
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
                    genesis_event_ref: operation
                        .payload
                        .get("event_id")
                        .and_then(Value::as_str)
                        .unwrap_or_else(|| operation.operation_id.as_str())
                        .to_owned(),
                    covered_seals: covered_seals.clone(),
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
            covered_seals,
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
                    covered_seals: covered_seals.clone(),
                    governance_binding: binding,
                    accepted_commit_ref: operation
                        .payload
                        .get("event_id")
                        .and_then(Value::as_str)
                        .unwrap_or_else(|| operation.operation_id.as_str())
                        .to_owned(),
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
    if kinds::canonical_kind_for_operation(operation)
        != Some(arkret_wire::events::EventKind::INVITE_CREATE)
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

pub async fn project_trusted_sidecar_member_operation(
    state: &AppState,
    controller: &str,
    operation: &Operation,
) {
    project_accepted_operations_inner(
        state,
        controller,
        "",
        std::slice::from_ref(operation),
        Some(controller),
    )
    .await;
}

async fn project_accepted_operations_inner(
    state: &AppState,
    origin: &str,
    source_device_id: &str,
    operations: &[Operation],
    trusted_sidecar_member_controller: Option<&str>,
) {
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
        } else if kinds::canonical_kind_string(operation) == "ak.invite.accept" {
            project_invite_accept_operation(state, origin, operation).await;
        } else if kinds::canonical_kind_string(operation)
            == arkret_wire::events::EventKind::INVITE_CANCEL
        {
            project_invite_cancel_operation(state, origin, operation).await;
        } else if kinds::canonical_kind_string(operation)
            == arkret_wire::events::EventKind::INVITE_REVOKE
        {
            project_invite_revoke_operation(state, origin, operation).await;
        } else if kinds::canonical_kind_string(operation) == "ak.realm.plaintext_visible_services" {
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
        if kinds::canonical_kind_string(operation)
            == arkret_wire::events::EventKind::MEMBER_IDENTITY_UPDATE
        {
            project_member_identity_update(state, operation);
        }
        // Cache ak.realm.read_receipt_policy state into ProjectionState so
        // ephemeral ak.receipt.read fanout (and other readers) can hit a
        // BTreeMap lookup instead of scanning the durable Event store.
        // (R1.2 renamed `ak.space.read_receipt_policy` to `ak.realm.*`.)
        if kinds::canonical_kind_string(operation) == "ak.realm.read_receipt_policy" {
            project_read_receipt_policy(state, operation);
        }
        if kinds::canonical_kind_string(operation) == "ak.account_data.set" {
            project_account_data_set(state, origin, source_device_id, operation).await;
        }
        crate::routing::identity::consent::project_consent_operation(state, operation).await;
        // Phase 4 — materialize accepted cross-signing publishes into the
        // cross-signing registry (CAS bookkeeping). Validation already ran pre-acceptance.
        if kinds::canonical_kind_string(operation) == "ak.cross_signing.publish" {
            crate::routing::identity::cross_signing::project_cross_signing_publish(
                state,
                &operation.payload,
            );
        }
        if kinds::canonical_kind_string(operation) == "ak.cross_signing.reset" {
            crate::routing::identity::cross_signing::project_cross_signing_reset(
                state,
                &operation.payload,
            )
            .await;
        }
        // Device-identity Phase 1 — persist an accepted `ak.device.authorize`'s
        // `payload.device_public_key` into the devices table so the
        // `keys/query` signing-key directory resolves devices that were
        // authorized but never opened a session (previously the key only
        // landed via the session-grant exchange path).
        if kinds::canonical_kind_string(operation)
            == arkret_wire::events::EventKind::DEVICE_AUTHORIZE
        {
            project_device_authorize(state, operation).await;
        }
        // Also apply to the deterministic reducer.
        // The canonical `ak.circle.member.state` payload is closed and does
        // not carry executor/capability verdict fields. For the already
        // authenticated sidecar aggregate only, supply those values to the
        // reducer on an internal clone. Persistence, sync, and projection
        // events below continue to use the untouched wire-clean operation.
        let reducer_context_operation = match kinds::canonical_kind_for_operation(operation) {
            Some(arkret_wire::events::EventKind::CIRCLE_MEMBER_STATE) => {
                Some(accepted_circle_member_reducer_operation(
                    operation,
                    trusted_sidecar_member_controller,
                ))
            }
            Some(arkret_wire::events::EventKind::MEMBER_STATE)
                if operation.payload.get("sender").is_none() =>
            {
                let mut contextual = operation.clone();
                contextual.payload["sender"] = Value::String(origin.to_owned());
                Some(contextual)
            }
            _ => None,
        };
        let reducer_operation = reducer_context_operation.as_ref().unwrap_or(operation);
        let reducer_effect =
            if actor_private_read_cursor_matches_origin(origin, source_device_id, operation) {
                let cell_writes = accepted_operation_cell_writes(state, origin, operation);
                Some(state.projections().apply_via_lattice_registry(
                    reducer_operation,
                    &cell_writes,
                    state.hlc(),
                ))
            } else {
                None
            };
        if let Some(effect) = reducer_effect {
            if kinds::canonical_kind_string(operation)
                == arkret_wire::events::EventKind::KEY_BACKUP_ACTIVE_SERIES
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
            if kinds::canonical_kind_string(operation)
                == arkret_wire::events::EventKind::REALM_KEY_SHARE
            {
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
        crate::routing::identity::account::retire_direct_bindings_for_operation(state, operation)
            .await;
        crate::routing::identity::account::project_canonical_direct_binding(state, operation).await;
        if kinds::canonical_kind_string(operation)
            == arkret_wire::events::EventKind::RELATION_CREATE
        {
            crate::routing::events::notify::dispatch_assignment_notifications(state, operation)
                .await;
        }
        if kinds::canonical_kind_string(operation) == arkret_wire::events::EventKind::STRAND_UPDATE
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
            tracing::warn!(%error, "failed to persist agent participation ceiling");
        }
        let projected = projection_event_from_operation(operation, Some(origin));
        // Persist before broadcast so subscribers never observe an event that
        // cannot participate in cursor replay.
        if let Err(error) = persist_and_publish_projection_event(state, projected).await {
            tracing::warn!(%error, "failed to persist projection event before publish");
        }
        if let Err(error) = persist_projected_operation(state, origin, operation).await {
            tracing::warn!(
                error = %error,
                operation_id = %operation.operation_id,
                object_kind = %operation.object_kind,
                "failed to persist accepted operation projection"
            );
        }
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

    let mut record = match operation.payload.clone() {
        Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };
    record
        .entry("appeal_id".to_owned())
        .or_insert_with(|| Value::String(appeal_id.clone()));
    record.insert(
        "event_kind".to_owned(),
        Value::String(kinds::canonical_kind_string(operation)),
    );
    record.insert("appeal_state".to_owned(), Value::String(new_state.clone()));
    record.entry("projected_at".to_owned()).or_insert_with(|| {
        Value::String(arkret_canonical::format_timestamp_canonical(
            operation.created_at,
        ))
    });
    if let Err(error) = state
        .governance()
        .append_moderation_appeal(Value::Object(record))
        .await
    {
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
    let sender_device_id = if source_device_id.trim().is_empty() {
        {
            operation
                .payload
                .get("sender_device_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
        }
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

    let expires_at = operation
        .payload
        .get("expires_at")
        .cloned()
        .unwrap_or_else(|| json!(operation.created_at + chrono::Duration::hours(1)));
    let welcome_content = operation.payload.clone();
    let content = json!({
        "kind": "ak.mls.welcome",
        "sender_device_id": sender_device_id,
        "expires_at": expires_at,
        "content": welcome_content,
        "unsigned": {
            "source_event_id": operation.operation_id,
            "mls_welcome_id": welcome_id,
            "key_package_id": record.key_package_id,
        }
    });
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
    let wire_payload =
        crate::routing::events::operations::projection_context_stripped_payload(&operation.payload);
    let Ok(share) = serde_json::from_value::<
        arkret_models_collaboration::events_payloads::RealmKeySharePayload,
    >(wire_payload.clone()) else {
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
    let sender_device_id = if source_device_id.trim().is_empty() {
        share.sender_device_id.as_str()
    } else {
        source_device_id.trim()
    };
    if sender_device_id.is_empty() {
        tracing::warn!(
            operation_id = %operation.operation_id,
            "cannot enqueue realm key share device message without sender device id"
        );
        return;
    }
    let content = realm_key_share_device_message_content(
        sender_device_id,
        operation.realm_id.as_str(),
        operation.operation_id.as_str(),
        &wire_payload,
    );
    let record = DeviceMessageState {
        idempotency_key: format!("realm_key_share:{}", operation.operation_id),
        sender: origin.to_owned(),
        recipient: share.recipient_principal_id.to_string(),
        device_id: recipient_device_id.to_string(),
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

fn realm_key_share_device_message_content(
    sender_device_id: &str,
    realm_id: &str,
    operation_id: &str,
    payload: &Value,
) -> Value {
    json!({
        "kind": arkret_wire::events::EventKind::REALM_KEY_SHARE,
        "sender_device_id": sender_device_id,
        "content": {
            "realm_id": realm_id,
            "operation_id": operation_id,
            "payload": payload,
        },
    })
}

/// Device-identity Phase 1 — persist an accepted `ak.device.authorize`'s
/// authoritative `device_public_key` into the devices inventory so the
/// `keys/query` signing-key directory (`device-lifecycle.md` §8.2) can resolve
/// a device that was authorized but never opened a session. Idempotent and
/// non-destructive: an existing row keeps its `created_at`, `display_name`,
/// revocation, any already-recorded `device_public_key`, and an atomically
/// projected B-model generation binding; a verified state is never downgraded.
/// The `cross_signing_binding` was already verified at ingest
/// (`validate_device_authorize_binding`).
async fn project_device_authorize(state: &crate::state::AppState, operation: &Operation) {
    use soland_services::identity::{DeviceIdentity, FindDeviceQuery, SaveDeviceCommand};
    let payload = &operation.payload;
    // Accepted device.authorize payloads already passed schema validation;
    // parse the wire shape (projection-injected envelope fields stripped)
    // into the typed SDK counterpart so field access is checked, not stringly.
    let wire_payload =
        crate::routing::identity::cross_signing::device_authorize_wire_payload(payload);
    let typed: arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload = match serde_json::from_value(wire_payload) {
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
    let operation_uuid = ids::typed_uuid_part_expect_internal(operation.operation_id.as_str());
    let authorize_event_id = ids::format_typed_uuid("event", &operation_uuid);
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
        // Tier-2 (device-lifecycle.md §5.2 / §8.2): persist the authoritative
        // `cross_signing_binding` verbatim so keys/query can echo it for
        // client-side chain verification.
        match payload.get("cross_signing_binding") {
            Some(binding @ Value::Object(_)) => {
                map.insert("cross_signing_binding".to_owned(), binding.clone());
            }
            _ => {
                map.remove("cross_signing_binding");
            }
        }
        // Service-attested devices carry the delegated enrollment authority
        // binding instead of cross-signing material. Persist it verbatim so
        // keys/query can expose the current device-set trust anchor.
        match payload.get("enrollment_authority_binding") {
            Some(binding @ Value::Object(_)) => {
                map.insert("enrollment_authority_binding".to_owned(), binding.clone());
            }
            _ => {
                map.remove("enrollment_authority_binding");
            }
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

    #[tokio::test]
    async fn realm_key_share_device_projection_accepts_projected_payload_context() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let realm_id = arkret_identifiers::RealmId::new(
            "ak:realm:0196419b-1000-7000-8000-000000000101".to_owned(),
        )
        .unwrap();
        let operation_id = arkret_identifiers::OperationId::new(
            "ak:operation:0196419b-1000-7000-8000-000000000102",
        )
        .unwrap();
        let sender = "did:web:alice.example";
        let sender_device = "ak:device:01904100-0000-7000-8000-a11ce0000101";
        let recipient = "did:web:bob.example";
        let recipient_device = "ak:device:01904100-0000-7000-8000-b0b000000101";
        let payload = json!({
            "share_kind": "member_device",
            "recipient_principal_id": recipient,
            "recipient_device_id": recipient_device,
            "sender_device_id": sender_device,
            "source_authorization_ref": "ak:event:01904100-0000-7000-8000-0000000001a1",
            "sender_device_signature": {
                "alg": "Ed25519",
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
            "created_at": "2026-07-05T00:00:00.000Z",
            "event_id": "ak:event:01904100-0000-7000-8000-000000000101",
            "sender": sender,
            "hlc": "2026-07-05T00:00:00.000Z/node/1"
        });
        let operation = Operation::create(
            operation_id.clone(),
            realm_id,
            arkret_wire::events::EventKind::REALM_KEY_SHARE,
            payload,
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
            arkret_wire::events::EventKind::REALM_KEY_SHARE
        );
        assert_eq!(
            queued[0].content["content"]["payload"]["ciphertext"],
            "sealed"
        );
        assert!(
            queued[0].content["content"]["payload"]
                .get("event_id")
                .is_none()
        );
        assert!(
            queued[0].content["content"]["payload"]
                .get("sender")
                .is_none()
        );
        assert!(queued[0].content["content"]["payload"].get("hlc").is_none());
    }

    #[test]
    fn realm_key_share_device_projection_preserves_payload_in_envelope_content() {
        let realm_id = "ak:realm:0196419b-1000-7000-8000-000000000001";
        let operation_id = "ak:operation:0196419b-1000-7000-8000-000000000002";
        let sender = "did:web:alice.example";
        let sender_device = "ak:device:01904100-0000-7000-8000-a11ce0000001";
        let recipient = "did:web:bob.example";
        let recipient_device = "ak:device:01904100-0000-7000-8000-b0b000000001";
        let payload = json!({
            "share_kind": "member_device",
            "recipient_principal_id": recipient,
            "recipient_device_id": recipient_device,
            "sender_device_id": sender_device,
            "source_authorization_ref": "ak:event:01904100-0000-7000-8000-0000000000a1",
            "sender_device_signature": {
                "alg": "EdDSA",
                "kid": "did:web:alice.example#ak:device:01904100-0000-7000-8000-a11ce0000001",
                "sig": "signature"
            },
            "key_scope": {
                "effective_scope": {"realm_id": realm_id},
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
        let mut content =
            realm_key_share_device_message_content(sender_device, realm_id, operation_id, &payload);
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
            delivered[0].kind,
            arkret_wire::events::EventKind::REALM_KEY_SHARE
        );
        assert_eq!(delivered[0].content["realm_id"], realm_id);
        assert_eq!(delivered[0].content["operation_id"], operation_id);
        assert_eq!(delivered[0].content["payload"], payload);
    }

    #[test]
    fn accepted_circle_member_context_does_not_mutate_wire_operation() {
        let operation = Operation::create(
            arkret_identifiers::OperationId::new(
                "ak:operation:0196419b-1000-7000-8000-000000000202".to_owned(),
            )
            .unwrap(),
            arkret_identifiers::RealmId::new(
                "ak:realm:0196419b-1000-7000-8000-000000000201".to_owned(),
            )
            .unwrap(),
            arkret_wire::events::EventKind::CIRCLE_MEMBER_STATE,
            json!({
                "circle_id": "ak:circle:0196419b-1000-7000-8000-000000000203",
                "actor_id": "did:web:agent.example",
                "membership": "join"
            }),
        );

        let contextual = accepted_circle_member_reducer_operation(
            &operation,
            Some("did:web:controller.example"),
        );

        assert!(operation.payload.get("sender").is_none());
        assert!(
            operation
                .payload
                .get("manage_capability_verified")
                .is_none()
        );
        assert_eq!(contextual.payload["sender"], "did:web:controller.example");
        assert_eq!(contextual.payload["manage_capability_verified"], true);
    }
}
