use cokret_sdk::Operation;
use serde_json::{Value, json};

use super::*;
use crate::kinds;
use crate::persistence::{MlsKeyPackageRow, MlsWelcomeRecord};
use crate::reducer::MlsWelcomeQueueKey;
use crate::state::AppState;

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

pub(super) async fn mirror_mls_effect_to_persistence(
    state: &AppState,
    operation: &Operation,
    effect: &crate::reducer::ProjectionEffect,
) {
    let crate::reducer::ProjectionEffect::Mls(effect) = effect else {
        return;
    };

    match effect {
        crate::reducer::MlsEffect::KeyPackagePublished { keypackage_id, .. } => {
            let record = state
                .projection
                .lock()
                .ok()
                .and_then(|projection| projection.mls_key_packages.get(keypackage_id).cloned())
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
                    lifetime_not_before: kp.lifetime.not_before,
                    lifetime_not_after: kp.lifetime.not_after,
                    claimed_by_mls_group_id: kp.claimed_by,
                    ssk_generation: kp.ssk_generation,
                    consumed_at: kp.consumed_at,
                    created_at: kp.created_at,
                });
            if let Some(record) = record {
                if let Err(error) = state.persistence.mls_key_packages().put(&record).await {
                    tracing::warn!(%error, keypackage_id = %keypackage_id, "failed to mirror MLS KeyPackage publish");
                }
            }
        }
        crate::reducer::MlsEffect::KeyPackageClaimed {
            keypackage_id,
            group_id,
            consumed_at,
        } => {
            if let Err(error) = state
                .persistence
                .mls_key_packages()
                .try_claim(keypackage_id, group_id, None, *consumed_at)
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
            let record = state
                .projection
                .lock()
                .ok()
                .and_then(|projection| {
                    projection
                        .mls_welcomes
                        .get(&MlsWelcomeQueueKey::new(
                            recipient_actor_id.clone(),
                            recipient_device_id.clone(),
                        ))
                        .and_then(|queue| queue.iter().find(|row| row.id == *welcome_id))
                        .cloned()
                })
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
            }
        }
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
        }
    }
}

/// After the deterministic reducer mutates the in-memory
/// `ProjectionState::{space_containers,strands,morphs}` maps for a
/// Space-container / Strand / Morph lifecycle event, snapshot the affected entry (under
/// projection lock) and upsert it to the corresponding
/// `SpaceContainerProjectionStore` / `StrandProjectionStore` / `MorphProjectionStore`
/// in persistence. Lock is released BEFORE the persistence write so
/// any backend latency doesn't stall other reducer paths.
///
/// Unknown / unrelated kinds are no-ops. Lookup misses (e.g. archive
/// for an unknown object — reducer tolerates this for causal /
/// backfill ordering) also produce no write.
async fn write_through_projection(state: &AppState, operation: &Operation) {
    use crate::kinds;
    use crate::persistence::{
        MorphProjectionRecord, SpaceContainerProjectionRecord, StrandProjectionRecord,
    };
    use crate::reducer::{ObjectLifecycleState, SpaceContainerLifecycleState};

    enum Snapshot {
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
        kinds::CK_SPACE_CONTAINER_CREATE
            | kinds::CK_SPACE_CONTAINER_UPDATE
            | kinds::CK_SPACE_CONTAINER_PARENT
            | kinds::CK_SPACE_CONTAINER_ARCHIVE
            | kinds::CK_SPACE_CONTAINER_RESTORE
            | kinds::CK_SPACE_CONTAINER_TOMBSTONE
    );
    // Strand lifecycle (state-affecting + position-touching).
    let is_strand_kind = matches!(
        kind,
        kinds::CK_STRAND_CREATE
            | kinds::CK_STRAND_UPDATE
            | kinds::CK_STRAND_ARCHIVE
            | kinds::CK_STRAND_RESTORE
            | kinds::CK_STRAND_MOVE
            | kinds::CK_STRAND_REORDER
            | kinds::CK_STRAND_TRACKS_UPDATE
    );
    let is_morph_kind = matches!(
        kind,
        kinds::CK_MORPH_CREATE
            | kinds::CK_MORPH_UPDATE
            | kinds::CK_MORPH_ARCHIVE
            | kinds::CK_MORPH_RESTORE
    );
    // ck.redaction with an `object_ref` may have flipped a Strand or
    // Morph to Redacted. Pick up either by attempting both.
    let is_redaction = kind == kinds::CK_REDACTION;
    if !(is_space_container_kind || is_strand_kind || is_morph_kind || is_redaction) {
        return;
    }

    let snapshot = {
        let Ok(proj) = state.projection.lock() else {
            return;
        };
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
        let strand_id_from_object = operation
            .payload
            .get("object")
            .and_then(|v| v.get("id"))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let morph_id_from_payload = operation
            .payload
            .get("morph_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let morph_id_from_object = operation
            .payload
            .get("object")
            .and_then(|v| v.get("id"))
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
            let id = strand_id_from_payload.or(strand_id_from_object);
            id.and_then(|i| proj.strands.get(&i))
                .map(return_snapshot_strand)
        } else if is_morph_kind {
            let id = morph_id_from_payload.or(morph_id_from_object);
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
    ) -> Option<Snapshot> {
        Some(Snapshot::SpaceContainer(SpaceContainerProjectionRecord {
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
            updated_by: p.updated_by.clone(),
            updated_at: p.updated_at,
        }))
    }

    fn return_snapshot_strand(f: &crate::reducer::StrandProjection) -> Snapshot {
        Snapshot::Strand(StrandProjectionRecord {
            strand_id: f.strand_id.clone(),
            realm_id: f.realm_id.clone(),
            tracks: f.tracks.clone(),
            title: f.title.clone(),
            summary: f.summary.clone(),
            state: object_state_str(f.state).to_owned(),
            state_changed_at: f.state_changed_at,
            created_by: f.created_by.clone(),
            created_at: f.created_at,
            updated_by: f.updated_by.clone(),
            updated_at: f.updated_at,
            scope_circle_id: f.scope_circle_id.clone(),
        })
    }

    fn return_snapshot_morph(m: &crate::reducer::MorphProjection) -> Snapshot {
        Snapshot::Morph(MorphProjectionRecord {
            morph_id: m.morph_id.clone(),
            realm_id: m.realm_id.clone(),
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
        Snapshot::SpaceContainer(r) => {
            state
                .persistence
                .space_container_projections()
                .put(&r)
                .await
        }
        Snapshot::Strand(r) => state.persistence.strand_projections().put(&r).await,
        Snapshot::Morph(r) => state.persistence.morph_projections().put(&r).await,
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
        } else if kinds::canonical_kind_string(operation) == "ck.invite.accept" {
            project_invite_accept_operation(state, origin, operation).await;
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
        if kinds::canonical_kind_string(operation) == kinds::CK_MEMBER_IDENTITY_UPDATE {
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
            );
        }
        // Device-identity Phase 1 — persist an accepted `ck.device.authorize`'s
        // `payload.device_public_key` into the devices table so the
        // `keys/query` signing-key directory resolves devices that were
        // authorized but never opened a session (previously the key only
        // landed via the session-grant exchange path).
        if kinds::canonical_kind_string(operation) == kinds::CK_DEVICE_AUTHORIZE {
            project_device_authorize(state, &operation.payload).await;
        }
        // Also apply to the deterministic reducer.
        let reducer_effect =
            if actor_private_read_cursor_matches_origin(origin, source_device_id, operation) {
                state
                    .projection
                    .lock()
                    .ok()
                    .map(|mut proj| apply_via_lattice_registry(state, &mut proj, operation))
            } else {
                None
            };
        if let Some(effect) = reducer_effect {
            fanout_projection_effect_private_update(state, origin, source_device_id, &effect).await;
            mirror_mls_effect_to_persistence(state, operation, &effect).await;
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
        {
            if let Err(error) = state
                .persistence
                .agent_participation()
                .put_ceiling(record)
                .await
            {
                tracing::warn!(%error, "failed to persist agent participation ceiling");
            }
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

/// Device-identity Phase 1 — persist an accepted `ck.device.authorize`'s
/// authoritative `device_public_key` into the devices inventory so the
/// `keys/query` signing-key directory (`device-lifecycle.md` §8.2) can resolve
/// a device that was authorized but never opened a session. Idempotent and
/// non-destructive: an existing row keeps its `created_at`, `display_name`,
/// revocation, and any already-recorded `device_public_key`; a verified state
/// is never downgraded. The `cross_signing_binding` was already verified at
/// ingest (`validate_device_authorize_binding`).
async fn project_device_authorize(state: &crate::state::AppState, payload: &Value) {
    use crate::state::DeviceInventoryRecord;
    let Some(principal_id) = payload.get("principal_id").and_then(Value::as_str) else {
        return;
    };
    let Some(device_id) = payload.get("device_id").and_then(Value::as_str) else {
        return;
    };
    let device_public_key = payload
        .get("device_public_key")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let Some(device_public_key) = device_public_key else {
        // No key to project; nothing the directory needs from this event.
        return;
    };
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
        map.insert("device_authorize_projected".to_owned(), Value::Bool(true));
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
        let derived = state
            .projection
            .lock()
            .ok()
            .and_then(|proj| proj.effective_engine_grant(&grant_id));
        match derived {
            Some(grant) => state.authz.upsert_projected_grant(grant),
            // Cell present only as a revoke-before-grant tombstone (no
            // resolvable body / no actions): mark the index entry revoked if
            // we hold one.
            None => state.authz.mark_projected_grant_revoked(&grant_id),
        }
    }
}
