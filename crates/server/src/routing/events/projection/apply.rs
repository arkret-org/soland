use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cokret_sdk::Operation;
use serde_json::{Value, json};

use super::*;
use crate::persistence::{MlsKeyPackageRow, MlsWelcomeRecord};
use crate::reducer::MlsWelcomeQueueKey;
use crate::state::{AppState, DeviceMessageRecord};
use crate::{ids, kinds};

pub async fn project_accepted_operations_from_device(
    state: &AppState,
    origin: &str,
    source_device_id: &str,
    operations: &[Operation],
) {
    project_accepted_operations_inner(state, origin, source_device_id, operations).await;
}

pub(super) fn apply_via_lattice_registry(
    state: &AppState,
    proj: &mut crate::reducer::ProjectionState,
    operation: &Operation,
) -> crate::reducer::ProjectionEffect {
    let registry = crate::reducer::lattice_kinds::default_lattice_registry();
    proj.apply_via_lattice_registry(operation, &state.hlc, &registry)
}

pub(crate) async fn mirror_mls_effect_to_persistence(
    state: &AppState,
    origin: &str,
    source_device_id: &str,
    operation: &Operation,
    effect: &crate::reducer::ProjectionEffect,
) {
    let crate::reducer::ProjectionEffect::Mls(effect) = effect else {
        return;
    };

    match effect {
        crate::reducer::MlsEffect::KeyPackagePublished { keypackage_id, .. } => {
            let record = {
                let projection = state.projection.lock();
                projection.mls_key_packages.get(keypackage_id).cloned()
            }
                .map(|kp| MlsKeyPackageRow {
                    id: kp.id,
                    keypackage_ref: kp.keypackage_ref,
                    keypackage_digest: kp.keypackage_digest,
                    actor_id: kp.actor_id,
                    device_id: kp.device_id,
                    key_package_bytes: kp.key_package_bytes,
                    capabilities: kp.capabilities,
                    capabilities_digest: kp.capabilities_digest,
                    device_signature: kp.device_signature,
                    last_resort: kp.last_resort,
                    last_resort_realm_id: kp.last_resort_realm_id,
                    lifetime_not_before: kp.lifetime.not_before,
                    lifetime_not_after: kp.lifetime.not_after,
                    claimed_by_mls_group_id: kp.claimed_by,
                    ssk_generation: kp.ssk_generation,
                    device_authorize_event_id: kp.device_authorize_event_id,
                    consumed_at: kp.consumed_at,
                    created_at: kp.created_at,
                });
            if let Some(record) = record
                && let Err(error) = state.persistence.mls_key_packages().put(&record).await
            {
                tracing::warn!(%error, keypackage_id = %keypackage_id, "failed to mirror MLS KeyPackage publish");
            }
        }
        crate::reducer::MlsEffect::KeyPackageClaimed {
            keypackage_id,
            group_id,
            intended_realm_id,
            consumed_at,
            ..
        } => {
            if let Err(error) = state
                .persistence
                .mls_key_packages()
                .try_claim(
                    keypackage_id,
                    group_id,
                    intended_realm_id.as_deref(),
                    None,
                    None,
                    *consumed_at,
                )
                .await
            {
                tracing::warn!(%error, keypackage_id = %keypackage_id, "failed to mirror MLS KeyPackage claim");
            }
        }
        crate::reducer::MlsEffect::WelcomeEnqueued {
            welcome_id,
            recipient_actor_id,
            recipient_device_id,
            ..
        } => {
            let record = {
                let projection = state.projection.lock();
                {
                    projection
                        .mls_welcomes
                        .get(&MlsWelcomeQueueKey::new(
                            recipient_actor_id.clone(),
                            recipient_device_id.clone(),
                        ))
                        .and_then(|queue| queue.iter().find(|row| row.id == *welcome_id))
                        .cloned()
                }
            }
                .map(|welcome| MlsWelcomeRecord {
                    id: welcome.id,
                    group_id: welcome.group_id,
                    recipient_actor_id: welcome.recipient_actor_id,
                    recipient_device_id: welcome.recipient_device_id,
                    welcome_bytes: welcome.welcome_bytes,
                    key_package_id: welcome.key_package_id,
                    enqueued_at: welcome.enqueued_at,
                    delivered_at: welcome.delivered_at,
                });
            if let Some(record) = record {
                if let Err(error) = state.persistence.mls_welcomes().enqueue(&record).await {
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
        crate::reducer::MlsEffect::RemoveProposalRecorded { .. } => {}
        crate::reducer::MlsEffect::GroupGenesis {
            group_id,
            effective_scope,
            creator_actor_id,
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
                .persistence
                .mls_commits()
                .initialize_genesis(
                    effective_scope,
                    group_id,
                    creator_actor_id,
                    covered_seals,
                    &binding,
                    operation.created_at.timestamp(),
                )
                .await
            {
                tracing::warn!(%error, group_id = %group_id, "failed to mirror MLS genesis epoch");
            }
            bind_circle_mls_group(state, group_id, effective_scope, false);
        }
        crate::reducer::MlsEffect::CommitEpochAdvanced {
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
                .persistence
                .mls_commits()
                .try_bump(
                    effective_scope,
                    group_id,
                    *previous_epoch,
                    leader_actor_id,
                    covered_seals,
                    &binding,
                    operation.created_at.timestamp(),
                )
                .await
            {
                tracing::warn!(%error, group_id = %group_id, "failed to mirror MLS commit epoch");
            }
            bind_circle_mls_group(state, group_id, effective_scope, true);
        }
        crate::reducer::MlsEffect::CommitFrontierContested {
            group_id,
            effective_scope,
            epoch,
        } => {
            // §2.5.2 — concurrent commits drove `covered_frontier_cell` to `⊥`.
            // Mirror the contested marker onto the durable epoch row so the
            // group stays fail-closed (`decryption_pending`) across restarts
            // until a resolving commit advances the epoch.
            if let Err(error) = state
                .persistence
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
    let Some((realm_id, circle_id)) = circle_scope_parts(effective_scope) else {
        return;
    };

    let mut projection = state.projection.lock();
    {
        let Some(circle) = projection.circles.get_mut(&circle_id) else {
            tracing::warn!(%realm_id, %circle_id, %group_id, "MLS circle scope has no Circle projection");
            return;
        };
        if circle.realm_id != realm_id {
            tracing::warn!(%realm_id, %circle_id, circle_realm_id = %circle.realm_id, %group_id, "MLS circle scope realm mismatch");
            return;
        }
        if circle.encryption_profile != "mls_rfc9420" {
            tracing::warn!(%realm_id, %circle_id, %group_id, "MLS scope bound to non-MLS Circle projection");
            return;
        }
        match circle.mls_group_ref.as_deref() {
            Some(existing) if existing != group_id => {
                tracing::warn!(%realm_id, %circle_id, %group_id, existing, "MLS group mismatch for Circle projection");
                return;
            }
            Some(_) => {}
            None => {
                circle.mls_group_ref = Some(group_id.to_owned());
            }
        }
    }

    if clear_pending_removals {
        let before = projection.pending_mls_removals.len();
        projection.pending_mls_removals.retain(|obligation| {
            !(obligation.realm_id == realm_id
                && obligation.circle_id.as_deref() == Some(circle_id.as_str())
                && obligation
                    .mls_group_ref
                    .as_deref()
                    .is_none_or(|expected| expected == group_id))
        });
        let cleared = before.saturating_sub(projection.pending_mls_removals.len());
        if cleared > 0 {
            tracing::info!(%realm_id, %circle_id, %group_id, cleared, "cleared pending MLS remove obligations");
        }
    }
}

fn circle_scope_parts(effective_scope: &Value) -> Option<(String, String)> {
    let scope = effective_scope.as_object()?;
    if scope.get("kind").and_then(Value::as_str) != Some("circle") {
        return None;
    }
    let realm_id = scope.get("realm_id").and_then(Value::as_str)?.to_owned();
    let circle_id = scope.get("circle_id").and_then(Value::as_str)?.to_owned();
    Some((realm_id, circle_id))
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
    use crate::kinds;
    use crate::persistence::{
        MorphProjectionRecord, SpaceContainerProjectionRecord, StrandProjectionRecord,
    };
    use crate::reducer::{ObjectLifecycleState, SpaceContainerLifecycleState};

    enum ProjectionWriteThroughSnapshot {
        SpaceContainer(SpaceContainerProjectionRecord),
        Strand(StrandProjectionRecord),
        Morph(MorphProjectionRecord),
    }

    let Some(kind) = kinds::canonical_kind_for_operation(operation) else {
        return;
    };
    // Space-container lifecycle: 6 event kinds → space_containers map.
    let is_space_container_kind = matches!(
        kind,
        cokret_sdk::events::kinds::SPACE_CREATE
            | cokret_sdk::events::kinds::SPACE_UPDATE
            | cokret_sdk::events::kinds::SPACE_PARENT
            | cokret_sdk::events::kinds::SPACE_ARCHIVE
            | cokret_sdk::events::kinds::SPACE_RESTORE
            | cokret_sdk::events::kinds::SPACE_TOMBSTONE
    );
    // Strand lifecycle (state-affecting + position-touching).
    let is_strand_kind = matches!(
        kind,
        cokret_sdk::events::kinds::STRAND_CREATE
            | cokret_sdk::events::kinds::STRAND_UPDATE
            | cokret_sdk::events::kinds::STRAND_ARCHIVE
            | cokret_sdk::events::kinds::STRAND_RESTORE
            | cokret_sdk::events::kinds::STRAND_MOVE
            | cokret_sdk::events::kinds::STRAND_REORDER
            | cokret_sdk::events::kinds::STRAND_TRACKS_UPDATE
    );
    let is_morph_kind = matches!(
        kind,
        cokret_sdk::events::kinds::MORPH_CREATE
            | cokret_sdk::events::kinds::MORPH_UPDATE
            | cokret_sdk::events::kinds::MORPH_ARCHIVE
            | cokret_sdk::events::kinds::MORPH_RESTORE
    );
    // ck.redaction with an `object_ref` may have flipped a Strand or
    // Morph to Redacted. Pick up either by attempting both.
    let is_redaction = kind == cokret_sdk::events::kinds::REDACTION;
    if !(is_space_container_kind || is_strand_kind || is_morph_kind || is_redaction) {
        return;
    }

    let snapshot = {
        let proj = state.projection.lock();
        let container_space_id_from_payload = operation
            .payload
            .get("space_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let container_space_id_from_object = operation
            .payload
            .get("object")
            .and_then(|v| v.get("id"))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let strand_id_from_payload = operation
            .payload
            .get("strand_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let strand_id_from_target_ref = operation
            .payload
            .get("target_ref")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let strand_id_from_object = operation
            .payload
            .get("object")
            .and_then(|v| v.get("id"))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let morph_id_from_object = operation
            .payload
            .get("object")
            .and_then(|v| v.get("id"))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let morph_id_from_target_ref = operation
            .payload
            .get("target_ref")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let object_ref = operation
            .payload
            .get("object_ref")
            .or_else(|| operation.payload.get("target_object_ref"))
            .or_else(|| operation.payload.get("target_ref"))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);

        // Space-container candidates.
        if is_space_container_kind {
            let id = container_space_id_from_payload.or(container_space_id_from_object);
            if let Some(container) = id.and_then(|i| proj.space_containers.get(&i)) {
                return_snapshot_space_container(container)
            } else {
                None
            }
        } else if is_strand_kind {
            let id = if kind == cokret_sdk::events::kinds::STRAND_CREATE {
                strand_id_from_object
            } else if matches!(
                kind,
                cokret_sdk::events::kinds::STRAND_UPDATE
                    | cokret_sdk::events::kinds::STRAND_ARCHIVE
                    | cokret_sdk::events::kinds::STRAND_RESTORE
            ) {
                strand_id_from_target_ref
            } else {
                strand_id_from_payload
            };
            id.and_then(|i| proj.strands.get(&i))
                .map(return_snapshot_strand)
        } else if is_morph_kind {
            let id = if kind == cokret_sdk::events::kinds::MORPH_CREATE {
                morph_id_from_object
            } else {
                morph_id_from_target_ref
            };
            id.and_then(|i| proj.morphs.get(&i))
                .map(return_snapshot_morph)
        } else if is_redaction {
            // object_ref may be ck:strand: or ck:morph:; try both.
            if let Some(ref obj_ref) = object_ref {
                if let Some(strand) = proj.strands.get(obj_ref) {
                    Some(return_snapshot_strand(strand))
                } else {
                    proj.morphs.get(obj_ref).map(return_snapshot_morph)
                }
            } else {
                None
            }
        } else {
            None
        }
    };

    let Some(snapshot) = snapshot else {
        return;
    };

    fn return_snapshot_space_container(
        p: &crate::reducer::SpaceContainerProjection,
    ) -> Option<ProjectionWriteThroughSnapshot> {
        Some(ProjectionWriteThroughSnapshot::SpaceContainer(
            SpaceContainerProjectionRecord {
                container_space_id: p.container_space_id.clone(),
                realm_id: p.realm_id.clone(),
                kind: p.kind.clone(),
                title: p.title.clone(),
                scope_circle_id: p.scope_circle_id.clone(),
                default_scope_circle_id: p.default_scope_circle_id.clone(),
                child_scope_policy: p
                    .child_scope_policy
                    .as_ref()
                    .map(|policy| policy.kind.clone()),
                child_scope_policy_scope_circle_id: p
                    .child_scope_policy
                    .as_ref()
                    .and_then(|policy| policy.scope_circle_id.clone()),
                child_scope_policy_metadata_encryption_floor: p
                    .child_scope_policy
                    .as_ref()
                    .and_then(|policy| policy.metadata_encryption_floor.clone()),
                parent_ref: p.parent_ref.clone(),
                rank: p.rank.clone(),
                state: match p.state {
                    SpaceContainerLifecycleState::Active => "active",
                    SpaceContainerLifecycleState::Archived => "archived",
                    SpaceContainerLifecycleState::Tombstoned => "tombstoned",
                }
                .to_owned(),
                state_changed_at: p.state_changed_at,
                created_by: p.created_by.clone(),
                created_at: p.created_at,
                history_basis_seals: p.history_basis_seals.clone(),
                updated_by: p.updated_by.clone(),
                updated_at: p.updated_at,
            },
        ))
    }

    fn return_snapshot_strand(
        f: &crate::reducer::StrandProjection,
    ) -> ProjectionWriteThroughSnapshot {
        ProjectionWriteThroughSnapshot::Strand(StrandProjectionRecord {
            strand_id: f.strand_id.clone(),
            realm_id: f.realm_id.clone(),
            tracks: f.tracks.clone(),
            title: f.title.clone(),
            summary: f.summary.clone(),
            state: object_state_str(f.state).to_owned(),
            state_changed_at: f.state_changed_at,
            created_by: f.created_by.clone(),
            created_at: f.created_at,
            history_basis_seals: f.history_basis_seals.clone(),
            updated_by: f.updated_by.clone(),
            updated_at: f.updated_at,
            scope_circle_id: f.scope_circle_id.clone(),
        })
    }

    fn return_snapshot_morph(
        m: &crate::reducer::MorphProjection,
    ) -> ProjectionWriteThroughSnapshot {
        ProjectionWriteThroughSnapshot::Morph(MorphProjectionRecord {
            morph_id: m.morph_id.clone(),
            realm_id: m.realm_id.clone(),
            scope_circle_id: m.scope_circle_id.clone(),
            morph_type: m.morph_type.clone(),
            title: m.title.clone(),
            fields: serde_json::Value::Object(
                m.fields
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect(),
            ),
            schema_refs: json!(m.schema_refs),
            facets: json!(m.facets),
            versions: json!(m.versions),
            state: object_state_str(m.state).to_owned(),
            state_changed_at: m.state_changed_at,
            created_by: m.created_by.clone(),
            created_at: m.created_at,
            history_basis_seals: m.history_basis_seals.clone(),
            updated_by: m.updated_by.clone(),
            updated_at: m.updated_at,
        })
    }

    fn object_state_str(s: ObjectLifecycleState) -> &'static str {
        match s {
            ObjectLifecycleState::Active => "active",
            ObjectLifecycleState::Archived => "archived",
            ObjectLifecycleState::Redacted => "redacted",
        }
    }

    let result = match snapshot {
        ProjectionWriteThroughSnapshot::SpaceContainer(r) => {
            state
                .persistence
                .space_container_projections()
                .put(&r)
                .await
        }
        ProjectionWriteThroughSnapshot::Strand(r) => {
            state.persistence.strand_projections().put(&r).await
        }
        ProjectionWriteThroughSnapshot::Morph(r) => {
            state.persistence.morph_projections().put(&r).await
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
    project_accepted_operations_inner(state, origin, "", operations).await;
}

async fn project_accepted_operations_inner(
    state: &AppState,
    origin: &str,
    source_device_id: &str,
    operations: &[Operation],
) {
    for operation in operations {
        tracing::debug!(
            kind = ?crate::kinds::canonical_kind_for_operation(operation),
            realm_id = %operation.realm_id,
            origin = %origin,
            "project_accepted_operations"
        );
        ensure_projected_realm(state, origin, operation).await;
        if kinds::operation_is_message_create(operation) {
            project_federated_message(state, origin, operation).await;
            // CKP-0016 §9.4.5 — derive mention notifications with the agent
            // third-party mention gate.
            crate::routing::events::notify::dispatch_message_notifications(state, operation).await;
        } else if kinds::operation_is_invite_create(operation) {
            project_invite_create_operation(state, origin, operation).await;
        } else if kinds::operation_is_invite_third_party(operation) {
            project_invite_third_party_operation(state, operation).await;
        } else if kinds::operation_is_invite_claim(operation) {
            project_invite_claim_operation(state, operation).await;
        } else if kinds::canonical_kind_string(operation) == "ck.invite.accept" {
            project_invite_accept_operation(state, origin, operation).await;
        } else if kinds::canonical_kind_string(operation)
            == cokret_sdk::events::kinds::INVITE_CANCEL
        {
            project_invite_cancel_operation(state, origin, operation).await;
        } else if kinds::canonical_kind_string(operation)
            == cokret_sdk::events::kinds::INVITE_REVOKE
        {
            project_invite_revoke_operation(state, origin, operation).await;
        } else if kinds::canonical_kind_string(operation) == "ck.realm.plaintext_visible_services" {
            project_plaintext_visible_services_operation(state, operation).await;
        } else if kinds::operation_is_membership(operation)
            || kinds::operation_is_realm_lifecycle(operation)
        {
            project_membership_operation(state, origin, operation).await;
        }
        // MID-3 (R3.1, cokret-spec @ 7157ee8) — persist accepted
        // `ck.member.identity.update` events into the in-memory registry.
        // Reducer-shape validation (segment whitelist, cross-cell guard,
        // digest binding) runs inside `project_member_identity_update`;
        // plaintext Ed25519 proof verification has already run at event
        // ingest, and unsupported proof forms fail closed there.
        if kinds::canonical_kind_string(operation)
            == cokret_sdk::events::kinds::MEMBER_IDENTITY_UPDATE
        {
            project_member_identity_update(state, operation);
        }
        // Cache ck.realm.read_receipt_policy state into ProjectionState so
        // ephemeral ck.receipt.read fanout (and other readers) can hit a
        // BTreeMap lookup instead of scanning the durable Event store.
        // (R1.2 renamed `ck.space.read_receipt_policy` to `ck.realm.*`.)
        if kinds::canonical_kind_string(operation) == "ck.realm.read_receipt_policy" {
            project_read_receipt_policy(state, operation);
        }
        if kinds::canonical_kind_string(operation) == "ck.account_data.set" {
            project_account_data_set(state, origin, source_device_id, operation).await;
        }
        crate::routing::identity::consent::project_consent_operation(state, operation).await;
        // Phase 4 — materialize accepted cross-signing publishes into the
        // DeviceManager (CAS bookkeeping). Validation already ran pre-acceptance.
        if kinds::canonical_kind_string(operation) == "ck.cross_signing.publish" {
            crate::routing::identity::cross_signing::project_cross_signing_publish(
                state,
                &operation.payload,
            );
        }
        if kinds::canonical_kind_string(operation) == "ck.cross_signing.reset" {
            crate::routing::identity::cross_signing::project_cross_signing_reset(
                state,
                &operation.payload,
            )
            .await;
        }
        // Device-identity Phase 1 — persist an accepted `ck.device.authorize`'s
        // `payload.device_public_key` into the devices table so the
        // `keys/query` signing-key directory resolves devices that were
        // authorized but never opened a session (previously the key only
        // landed via the session-grant exchange path).
        if kinds::canonical_kind_string(operation) == cokret_sdk::events::kinds::DEVICE_AUTHORIZE {
            project_device_authorize(state, operation).await;
        }
        // Also apply to the deterministic reducer.
        let reducer_effect =
            if actor_private_read_cursor_matches_origin(origin, source_device_id, operation) {
                {
                    let mut proj = state.projection.lock();
                    Some(apply_via_lattice_registry(state, &mut proj, operation))
                }
            } else {
                None
            };
        if let Some(effect) = reducer_effect {
            if matches!(
                &effect,
                crate::reducer::ProjectionEffect::RealmKeyShareProjected { .. }
            ) {
                project_realm_key_share_to_device(state, origin, source_device_id, operation).await;
            }
            fanout_projection_effect_private_update(state, origin, source_device_id, &effect).await;
            mirror_mls_effect_to_persistence(state, origin, source_device_id, operation, &effect)
                .await;
            mirror_moderation_effect_to_persistence(state, operation, &effect).await;
            // SOL-ORG-04 — persist an accepted `ck.realm.organization`
            // relationship statement projection durably.
            mirror_realm_organization_effect_to_persistence(state, &effect).await;
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
        write_through_projection(state, operation).await;
        // CKP-0016 — mirror agent_participation ceiling changes into the
        // agent_participation_ceiling projection table (read by
        // participation.set / .get ceiling resolution).
        if let Some(record) =
            crate::routing::events::operations::agent_participation_ceiling_record(operation)
            && let Err(error) = state
                .persistence
                .agent_participation()
                .put_ceiling(record)
                .await
        {
            tracing::warn!(%error, "failed to persist agent participation ceiling");
        }
        let projected = projection_event_from_operation(operation, Some(origin));
        // Broadcast every accepted projection
        // event to live subscribers on ck.events.subscribe. Subscribers
        // filter by `realm_id`. `send` returns Err only if there are no
        // active receivers — that's not an error path, it's the steady
        // state when no one's subscribed.
        let _ = state
            .event_broadcast
            .send(crate::state::EventNotification::event(
                projected.realm_id.clone(),
                projected.event_id.clone(),
                projection_event_json(&projected),
            ));
        append_projection_event(state, projected).await;
        if let Err(error) = persist_projected_operation(state, origin, operation).await {
            tracing::warn!(
                error = %error,
                operation_id = %operation.operation_id,
                object_type = %operation.object_type,
                "failed to persist accepted operation projection"
            );
        }
        // Reference applet bridge: if the accepted operation is
        // `ck.applet.interop_session.start`, emit a synthetic
        // `ck.applet.interop_session.status` (echo response)
        // immediately afterwards so the timeline observes the full
        // round trip without a real applet service plugged in. See
        // `routing::events::applet_bridge::maybe_emit_echo_status_for_session_start`
        // for the body shape contract.
        crate::routing::events::applet_bridge::maybe_emit_echo_status_for_session_start(
            state, origin, operation,
        )
        .await;
        // Reference agent runtime: if the accepted operation is
        // `ck.agent.interop_session.start`, fan out a synthetic
        // `ck.agent.interop_session.status` (running) followed by a
        // terminal `ck.agent.interop_session.result` (completed) with
        // an `audit_binding` placeholder so the lifecycle is observable
        // end-to-end. See
        // `routing::events::agent_bridge::maybe_emit_echo_result_for_session_start`.
        crate::routing::events::agent_bridge::maybe_emit_echo_result_for_session_start(
            state, origin, operation,
        )
        .await;
    }
}

pub(crate) async fn mirror_moderation_effect_to_persistence(
    state: &AppState,
    operation: &Operation,
    effect: &crate::reducer::ProjectionEffect,
) {
    let crate::reducer::ProjectionEffect::ModerationAppealProjected {
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
    record
        .entry("projected_at".to_owned())
        .or_insert_with(|| Value::String(operation.created_at.to_rfc3339()));
    if let Err(error) = state
        .persistence
        .moderation()
        .append_appeal(Value::Object(record))
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

/// SOL-ORG-04 — persist an accepted `ck.realm.organization` relationship
/// statement. The reducer has already verified (organization side) and
/// projected the row into `ProjectionState::realm_organization_statements`;
/// here we snapshot that row (under lock) and upsert it into the durable
/// `realm_organizations` table keyed by `(realm_id, organization_id,
/// relationship)`.
pub(crate) async fn mirror_realm_organization_effect_to_persistence(
    state: &AppState,
    effect: &crate::reducer::ProjectionEffect,
) {
    let crate::reducer::ProjectionEffect::RealmOrganizationProjected {
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
        let proj = state.projection.lock();
        proj.realm_organization_statements.get(&key).cloned()
    };
    let Some(row) = row else {
        return;
    };
    let record = crate::state::RealmOrganizationStatementRecord {
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
        .persistence
        .realm_organization_statements()
        .put(&record)
        .await
    {
        tracing::warn!(
            %error,
            realm_id = %record.realm_id,
            organization_id = %record.organization_id,
            relationship = %record.relationship,
            "failed to persist ck.realm.organization relationship statement"
        );
    }
}

async fn project_mls_welcome_to_device(
    state: &AppState,
    origin: &str,
    source_device_id: &str,
    operation: &Operation,
    record: &MlsWelcomeRecord,
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

    let epoch = operation
        .payload
        .get("epoch")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let expires_at = operation
        .payload
        .get("expires_at")
        .cloned()
        .unwrap_or_else(|| json!(operation.created_at + chrono::Duration::hours(1)));
    let content = json!({
        "kind": "ck.mls.welcome",
        "sender_device_id": sender_device_id,
        "expires_at": expires_at,
        "content": {
            "group_id": record.group_id,
            "epoch": epoch,
            "recipient_principal_id": record.recipient_actor_id,
            "recipient_device_id": record.recipient_device_id,
            "welcome": URL_SAFE_NO_PAD.encode(&record.welcome_bytes),
            "welcome_hash": cokret_sdk::canonical::sha256_digest(&record.welcome_bytes),
        },
        "unsigned": {
            "source_event_id": operation.operation_id,
            "mls_welcome_id": welcome_id,
            "key_package_id": record.key_package_id,
        }
    });
    let position = state.next_to_device_position();
    let recipient = record.recipient_actor_id.clone();
    let device = record.recipient_device_id.clone();
    let message = DeviceMessageRecord {
        idempotency_key: format!("mls_welcome:{welcome_id}"),
        sender: origin.to_owned(),
        recipient: recipient.clone(),
        device_id: device.clone(),
        position,
        content,
        created_at: operation.created_at,
    };
    tracing::warn!(
        target: "mls_welcome_delivery",
        %welcome_id,
        recipient = %recipient,
        device = %device,
        position,
        sender_device_id = %sender_device_id,
        "DIAG appending MLS Welcome to device_messages queue"
    );
    match state.persistence.device_messages().append(message).await {
        Ok(()) => tracing::warn!(
            target: "mls_welcome_delivery",
            %welcome_id, recipient = %recipient, device = %device, position,
            "DIAG MLS Welcome appended OK (ON CONFLICT DO NOTHING — if the row count is 0 a position/idempotency conflict swallowed it)"
        ),
        Err(error) => tracing::warn!(
            target: "mls_welcome_delivery",
            %error, %welcome_id, operation_id = %operation.operation_id,
            "DIAG failed to enqueue MLS Welcome to-device message"
        ),
    }
}

async fn project_realm_key_share_to_device(
    state: &AppState,
    origin: &str,
    source_device_id: &str,
    operation: &Operation,
) {
    let Ok(share) =
        serde_json::from_value::<cokret_sdk::RealmKeySharePayload>(operation.payload.clone())
    else {
        return;
    };
    // share_class=realm_recovery_key (recipient_device_id absent): the recipient is
    // an offline recovery org delivered via the durable Event, not a to-device
    // queue (encryption-and-audit.md §2.10.8). No device message is enqueued.
    let Some(recipient_device_id) = share.recipient_device_id.clone() else {
        return;
    };
    let sender_device_id = if source_device_id.trim().is_empty() {
        share.sender_device_id.trim()
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
        &operation.payload,
    );
    let record = DeviceMessageRecord {
        idempotency_key: format!("realm_key_share:{}", operation.operation_id),
        sender: origin.to_owned(),
        recipient: share.recipient_principal_id.to_string(),
        device_id: recipient_device_id,
        position: state.next_to_device_position(),
        content,
        created_at: operation.created_at,
    };
    if let Err(error) = state.persistence.device_messages().append(record).await {
        tracing::warn!(
            %error,
            operation_id = %operation.operation_id,
            "failed to enqueue realm key share to-device message"
        );
    }
}

/// Relay an ephemeral `ck.realm_key.request` to the provider device named by
/// `target_source_ref`. Mirrors [`project_realm_key_share_to_device`] /
/// [`project_mls_welcome_to_device`]: the request rides the provider device's
/// to-device queue so the provider can answer with a `ck.realm_key.share`.
///
/// Unlike the durable `ck.realm_key.share` projection, `ck.realm_key.request`
/// is wire-scope ephemeral (reducer_input=false) — there is no projected
/// operation here. The caller (the ephemeral relay) has already verified the
/// sender's membership/device signature and resolved the provider principal
/// that owns `target_device_id`; this function only enqueues the payload.
///
/// `idempotency_key` is prefixed `realm_key_request:` so a replayed request
/// (same envelope) collapses to a single queued message.
pub(crate) async fn project_realm_key_request_to_device(
    state: &AppState,
    origin: &str,
    sender_device_id: &str,
    realm_id: &str,
    request_id: &str,
    target_principal_id: &str,
    target_device_id: &str,
    payload: &Value,
    created_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
) {
    let sender_device_id = sender_device_id.trim();
    let target_device_id = target_device_id.trim();
    if target_device_id.is_empty() {
        tracing::warn!(
            %request_id,
            "cannot enqueue realm key request without a target device id"
        );
        return;
    }
    let content = realm_key_request_device_message_content(
        sender_device_id,
        realm_id,
        request_id,
        payload,
        expires_at,
    );
    let record = DeviceMessageRecord {
        idempotency_key: format!("realm_key_request:{request_id}"),
        sender: origin.to_owned(),
        recipient: target_principal_id.to_owned(),
        device_id: target_device_id.to_owned(),
        position: state.next_to_device_position(),
        content,
        created_at,
    };
    if let Err(error) = state.persistence.device_messages().append(record).await {
        tracing::warn!(
            %error,
            %request_id,
            "failed to enqueue realm key request to-device message"
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
        "kind": cokret_sdk::events::kinds::REALM_KEY_SHARE,
        "sender_device_id": sender_device_id,
        "content": {
            "realm_id": realm_id,
            "operation_id": operation_id,
            "payload": payload,
        },
    })
}

fn realm_key_request_device_message_content(
    sender_device_id: &str,
    realm_id: &str,
    request_id: &str,
    payload: &Value,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> Value {
    json!({
        "kind": "ck.realm_key.request",
        "sender_device_id": sender_device_id,
        "expires_at": expires_at,
        "content": {
            "realm_id": realm_id,
            "request_id": request_id,
            "payload": payload,
        },
    })
}

/// Device-identity Phase 1 — persist an accepted `ck.device.authorize`'s
/// authoritative `device_public_key` into the devices inventory so the
/// `keys/query` signing-key directory (`device-lifecycle.md` §8.2) can resolve
/// a device that was authorized but never opened a session. Idempotent and
/// non-destructive: an existing row keeps its `created_at`, `display_name`,
/// revocation, and any already-recorded `device_public_key`; a verified state
/// is never downgraded. The `cross_signing_binding` was already verified at
/// ingest (`validate_device_authorize_binding`).
async fn project_device_authorize(state: &crate::state::AppState, operation: &Operation) {
    use crate::state::DeviceInventoryRecord;
    let payload = &operation.payload;
    // Accepted device.authorize payloads already passed schema validation;
    // parse the wire shape (projection-injected envelope fields stripped)
    // into the typed SDK counterpart so field access is checked, not stringly.
    let wire_payload =
        crate::routing::identity::cross_signing::device_authorize_wire_payload(payload);
    let typed: cokret_sdk::DeviceAuthorizePayload = match serde_json::from_value(wire_payload) {
        Ok(typed) => typed,
        Err(error) => {
            tracing::warn!(%error, "accepted ck.device.authorize payload is not the typed wire shape; skipping projection");
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
        .persistence
        .devices()
        .get(principal_id, device_id)
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
            map.insert("hpke_key".to_owned(), Value::String(typed.hpke_key.clone()));
        }
        map.insert(
            "algorithms".to_owned(),
            Value::Array(
                typed
                    .algorithms
                    .iter()
                    .map(|algorithm| Value::String(algorithm.clone()))
                    .collect(),
            ),
        );
        map.insert("device_authorize_projected".to_owned(), Value::Bool(true));
        let operation_uuid = ids::typed_uuid_part_expect_internal(operation.operation_id.as_str());
        map.insert(
            "device_authorize_event_id".to_owned(),
            Value::String(ids::format_typed_uuid("event", &operation_uuid)),
        );
        // Tier-2 (device-lifecycle.md §5.2 / §8.2): persist the authoritative
        // `cross_signing_binding` verbatim so keys/query can echo it for
        // client-side chain verification. Inception bootstrap devices carry a
        // `bootstrap_binding` instead and no `cross_signing_binding`.
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
    let device = DeviceInventoryRecord {
        actor: principal_id.to_owned(),
        device_id: device_id.to_owned(),
        display_name,
        verification_state,
        payload: device_payload,
        created_at,
        updated_at,
        revoked_at,
    };
    if let Err(error) = state.persistence.devices().put(&device).await {
        tracing::warn!(%error, "failed to project ck.device.authorize device_public_key");
    }
}

/// P1 — fold a projected capability grant cell back into the
/// `SolandAuthzEngine` read index after the reducer wrote it. Called per
/// accepted capability event. The grant cell
/// (`ck.component.capability.grant.v1`) is the source of truth; this keeps
/// the engine's in-memory index (read by `SolandAuthzEngine::check`) in sync
/// with the projection without HTTP handlers writing it directly.
fn refresh_authz_index_from_capability_effect(
    state: &AppState,
    effect: &crate::reducer::ProjectionEffect,
) {
    use crate::reducer::ProjectionEffect;
    // CKP-0008 §4.5 / D3 — pairing completion clears
    // `effective_after_first_authorized_key` on the agent's pending grants;
    // re-fold each cleared grant so it enters the engine read index now that
    // it is active.
    let grant_ids: Vec<String> = match effect {
        ProjectionEffect::CapabilityGrantProjected { grant_id, .. }
        | ProjectionEffect::CapabilityRevokeProjected { grant_id, .. }
        | ProjectionEffect::CapabilityDelegateProjected { grant_id, .. } => vec![grant_id.clone()],
        ProjectionEffect::AgentKeyAuthorizeProjected {
            cleared_grant_ids, ..
        } => cleared_grant_ids.clone(),
        _ => return,
    };
    for grant_id in grant_ids {
        let derived = {
            let proj = state.projection.lock();
            proj.effective_engine_grant(&grant_id)
        };
        match derived {
            Some(grant) => state.authz.upsert_projected_grant(grant),
            // Cell present only as a revoke-before-grant tombstone (no
            // resolvable body / no actions): mark the index entry revoked if
            // we hold one.
            None => state.authz.mark_projected_grant_revoked(&grant_id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::identity::device_messages::device_message_envelopes_after;

    #[test]
    fn realm_key_share_device_projection_preserves_payload_in_envelope_content() {
        let realm_id = "ck:realm:0196419b-1000-7000-8000-000000000001";
        let operation_id = "ck:operation:0196419b-1000-7000-8000-000000000002";
        let sender = "did:web:alice.example";
        let sender_device = "ck:device:01904100-0000-7000-8000-a11ce0000001";
        let recipient = "did:web:bob.example";
        let recipient_device = "ck:device:01904100-0000-7000-8000-b0b000000001";
        let payload = json!({
            "share_class": "member_device",
            "recipient_principal_id": recipient,
            "recipient_device_id": recipient_device,
            "sender_device_id": sender_device,
            "sender_device_signature": {
                "alg": "EdDSA",
                "kid": "did:web:alice.example#ck:device:01904100-0000-7000-8000-a11ce0000001",
                "sig": "signature"
            },
            "key_scope": {
                "effective_scope": {"realm_id": realm_id},
                "from_epoch": 0,
                "to_epoch": 0
            },
            "ciphertext": "sealed",
            "aad_digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
            "created_at": "2026-06-30T00:00:00Z"
        });
        let created_at = chrono::Utc::now();
        let record = DeviceMessageRecord {
            idempotency_key: format!("realm_key_share:{operation_id}"),
            sender: sender.to_owned(),
            recipient: recipient.to_owned(),
            device_id: recipient_device.to_owned(),
            position: 1,
            content: realm_key_share_device_message_content(
                sender_device,
                realm_id,
                operation_id,
                &payload,
            ),
            created_at,
        };

        let delivered = device_message_envelopes_after(&[record]);
        assert_eq!(delivered.len(), 1);
        assert_eq!(
            delivered[0].kind,
            cokret_sdk::events::kinds::REALM_KEY_SHARE
        );
        assert_eq!(delivered[0].content["realm_id"], realm_id);
        assert_eq!(delivered[0].content["operation_id"], operation_id);
        assert_eq!(delivered[0].content["payload"], payload);
    }

    #[test]
    fn realm_key_request_device_projection_preserves_payload_in_envelope_content() {
        let realm_id = "ck:realm:0196419b-1000-7000-8000-000000000001";
        let request_id = "sha256:request";
        let sender = "did:web:bob.example";
        let sender_device = "ck:device:01904100-0000-7000-8000-b0b000000001";
        let recipient = "did:web:alice.example";
        let recipient_device = "ck:device:01904100-0000-7000-8000-a11ce0000001";
        let payload = json!({
            "key_scope": {
                "effective_scope": {"realm_id": realm_id},
                "from_epoch": 0,
                "to_epoch": 0
            },
            "recipient_principal_id": sender,
            "recipient_device_id": sender_device,
            "recipient_hpke_public_key": "cHVia2V5",
            "requested_source_class": "verified_member_device",
            "target_source_ref": recipient_device,
            "target_principal_id": recipient,
            "created_at": "2026-06-30T00:00:00Z"
        });
        let created_at = chrono::Utc::now();
        let expires_at = created_at + chrono::Duration::minutes(5);
        let record = DeviceMessageRecord {
            idempotency_key: format!("realm_key_request:{request_id}"),
            sender: sender.to_owned(),
            recipient: recipient.to_owned(),
            device_id: recipient_device.to_owned(),
            position: 1,
            content: realm_key_request_device_message_content(
                sender_device,
                realm_id,
                request_id,
                &payload,
                expires_at,
            ),
            created_at,
        };

        let delivered = device_message_envelopes_after(&[record]);
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].kind, "ck.realm_key.request");
        assert_eq!(delivered[0].content["realm_id"], realm_id);
        assert_eq!(delivered[0].content["request_id"], request_id);
        assert_eq!(delivered[0].content["payload"], payload);
        assert_eq!(delivered[0].expires_at, expires_at);
    }
}
